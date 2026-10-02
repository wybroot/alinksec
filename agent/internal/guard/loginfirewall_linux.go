//go:build linux

package guard

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const loginChain = "ALINKSEC_LOGIN"

func runLoginFirewall(ipv6 bool, args ...string) error {
	name := "iptables"
	if ipv6 {
		name = "ip6tables"
	}
	executable, err := exec.LookPath(name)
	if err != nil {
		executable, err = exec.LookPath(name + "-nft")
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, executable, append([]string{"-w", "2"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s: %w", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func missingLoginRule(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 1
}

func loginBlockPlatform(block loginBlock, enabled bool) error {
	ip, err := netip.ParseAddr(block.IP)
	if err != nil || ip.Zone() != "" {
		return fmt.Errorf("来源 IP 无效")
	}
	ip = ip.Unmap()
	ipv6 := ip.Is6()
	if enabled {
		if err := runLoginFirewall(ipv6, "-S", loginChain); err != nil {
			if !missingLoginRule(err) {
				return err
			}
			if err := runLoginFirewall(ipv6, "-N", loginChain); err != nil {
				return err
			}
		}
		if err := runLoginFirewall(ipv6, "-C", "INPUT", "-j", loginChain); err != nil {
			if !missingLoginRule(err) {
				return err
			}
			if err := runLoginFirewall(ipv6, "-I", "INPUT", "1", "-j", loginChain); err != nil {
				return err
			}
		}
	}
	comment := fmt.Sprintf("alinksec-login:%x", sha256.Sum256([]byte(block.RuleID)))[:31]
	for _, port := range block.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("SSH 端口无效")
		}
		rule := []string{loginChain, "-s", ip.String(), "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", comment, "-j", "DROP"}
		checkErr := runLoginFirewall(ipv6, append([]string{"-C"}, rule...)...)
		if checkErr != nil && !missingLoginRule(checkErr) {
			return checkErr
		}
		exists := checkErr == nil
		if enabled && !exists {
			if err := runLoginFirewall(ipv6, append([]string{"-A"}, rule...)...); err != nil {
				return err
			}
		}
		if !enabled && exists {
			if err := runLoginFirewall(ipv6, append([]string{"-D"}, rule...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// ClearLoginFirewall removes only the Agent-owned chain during authorized uninstall.
func ClearLoginFirewall() error {
	for _, ipv6 := range []bool{false, true} {
		if err := runLoginFirewall(ipv6, "-S", loginChain); err != nil {
			if missingLoginRule(err) || errors.Is(err, exec.ErrNotFound) {
				continue
			}
			return err
		}
		if err := runLoginFirewall(ipv6, "-D", "INPUT", "-j", loginChain); err != nil && !missingLoginRule(err) {
			return err
		}
		if err := runLoginFirewall(ipv6, "-F", loginChain); err != nil {
			return err
		}
		if err := runLoginFirewall(ipv6, "-X", loginChain); err != nil {
			return err
		}
	}
	return nil
}
