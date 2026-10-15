//go:build linux

package isolation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"net/netip"
)

const helperName = "watchdog"

type nativeFirewall struct{}

func newFirewall() firewall { return nativeFirewall{} }
func prepareBackends() ([]string, error) {
	var out []string
	for _, name := range []string{"iptables", "ip6tables"} {
		path, err := exec.LookPath(name)
		if err != nil {
			path, err = exec.LookPath(name + "-nft")
		}
		if err != nil {
			return nil, fmt.Errorf("dual-stack host isolation requires %s: %w", name, err)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		out = append(out, path)
		if _, err := ipt(path, "-S", "INPUT"); err != nil {
			return nil, fmt.Errorf("isolation backend unavailable: %w", err)
		}
	}
	return out, validateBackends(out)
}
func validateBackends(backends []string) error {
	if len(backends) != 2 {
		return fmt.Errorf("invalid dual-stack isolation backend")
	}
	for i, b := range backends {
		name := []string{"iptables", "ip6tables"}[i]
		if !filepath.IsAbs(b) || b != filepath.Clean(b) || filepath.Base(b) != name && filepath.Base(b) != name+"-nft" {
			return fmt.Errorf("invalid isolation firewall executable")
		}
	}
	return nil
}

// Bound subprocess output and lock wait as well as execution time. Selecting a
// backend is done once, before mutation; never mix legacy/nft rules on failure.
type limitedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 64*1024 - b.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	_, err := b.Buffer.Write(p)
	return n, err
}
func ipt(binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, append([]string{"-w", "1"}, args...)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if output.overflow {
		return "", fmt.Errorf("firewall response exceeded 64 KiB")
	}
	if err != nil {
		return output.String(), fmt.Errorf("%s %s: %w: %.1024s", filepath.Base(binary), strings.Join(args, " "), err, output.String())
	}
	return output.String(), nil
}
func absentRule(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 1
}
func chainName(l *Lease) string { return "ALKISO_" + l.ID[:16] }
func tag(l *Lease) string       { return "alinksec-isolation:" + l.ID }
func ownedRule(l *Lease, args ...string) []string {
	return append(append(args, "-m", "comment", "--comment", tag(l)), "-j", "RETURN")
}
func (nativeFirewall) apply(l *Lease) error {
	if err := validateBackends(l.Backends); err != nil {
		return err
	}
	chain := chainName(l)
	for family, b := range l.Backends {
		if _, err := ipt(b, "-N", chain); err != nil {
			return err
		}
		rules := [][]string{ownedRule(l, "-A", chain, "-i", "lo"), ownedRule(l, "-A", chain, "-o", "lo")}
		for _, ip := range l.IPs {
			a, _ := netip.ParseAddr(ip)
			if (family == 0) != a.Is4() {
				continue
			}
			port := fmt.Sprint(l.Port)
			rules = append(rules, ownedRule(l, "-A", chain, "-p", "tcp", "-d", ip, "--dport", port), ownedRule(l, "-A", chain, "-p", "tcp", "-s", ip, "--sport", port))
		}
		// IPv6 neighbor discovery is required to keep a permitted IPv6 management
		// connection reachable. It does not permit arbitrary transport traffic.
		if family == 1 {
			for _, typ := range []string{"133", "134", "135", "136"} {
				rules = append(rules, ownedRule(l, "-A", chain, "-p", "ipv6-icmp", "--icmpv6-type", typ))
			}
		}
		rules = append(rules, []string{"-A", chain, "-m", "comment", "--comment", tag(l), "-j", "DROP"})
		for _, args := range rules {
			if !time.Now().Before(l.Deadline) {
				return fmt.Errorf("isolation lease expired during apply")
			}
			if _, err := ipt(b, args...); err != nil {
				return err
			}
		}
		for _, hook := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			if !time.Now().Before(l.Deadline) {
				return fmt.Errorf("isolation lease expired during apply")
			}
			if _, err := ipt(b, "-I", hook, "1", "-m", "comment", "--comment", tag(l), "-j", chain); err != nil {
				return err
			}
		}
	}
	return nil
}
func (nativeFirewall) clear(l *Lease) error {
	if err := validateBackends(l.Backends); err != nil {
		return err
	}
	var failures []error
	for _, b := range l.Backends {
		if err := clearFamily(b, l); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
func clearFamily(binary string, l *Lease) error {
	chain := chainName(l)
	rules, err := ipt(binary, "-S", chain)
	if err != nil {
		if absentRule(err) && (strings.Contains(rules, "No chain/target/match") || strings.Contains(rules, "No such file or directory") || strings.Contains(rules, "does not exist")) {
			return nil
		}
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(rules), "\n") {
		if line == "-N "+chain {
			continue
		}
		if !strings.HasPrefix(line, "-A "+chain+" ") || !strings.Contains(line, "--comment "+tag(l)) && !strings.Contains(line, "--comment \""+tag(l)+"\"") {
			return fmt.Errorf("refusing to delete unrelated rules in isolation chain")
		}
	}
	for _, hook := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		args := []string{hook, "-m", "comment", "--comment", tag(l), "-j", chain}
		// A repeated cleanup is idempotent. Other failures must remain visible.
		if _, e := ipt(binary, append([]string{"-C"}, args...)...); e == nil {
			if _, e = ipt(binary, append([]string{"-D"}, args...)...); e != nil {
				return e
			}
		} else if !absentRule(e) {
			return e
		}
	}
	if _, err := ipt(binary, "-F", chain); err != nil {
		return err
	}
	_, err = ipt(binary, "-X", chain)
	return err
}
