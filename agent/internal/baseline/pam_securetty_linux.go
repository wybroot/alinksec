//go:build linux

package baseline

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const secureTTYPrefix = "scope=login-auth-securetty-declarations application_invocation_state=unverified identity_resolution_state=unverified module_integrity_state=unverified other_services_state=unverified terminal_delivery_state=unverified snapshot_state=non_atomic "

func checkPAMSecureTTY(cs *CheckSpec) ItemResult {
	return pamSecureTTYWithin(cs, systemPAMPaths(), "/etc/securetty", 0, 0)
}

// Only the fixed local unix/deny/permit auth topology is interpreted. The first
// securetty gate must retain failures, and noconsole avoids the kernel console
// exceptions. No authentication, NSS lookup, credential or terminal is probed.
func pamSecureTTYWithin(cs *CheckSpec, paths pamPaths, target string, uid, gid uint32) ItemResult {
	failure := func() ItemResult {
		return ItemResult{Error: true, Actual: secureTTYPrefix, Message: "securetty配置链、可信输入、模块或读取稳定性无法确认"}
	}
	r := newPAMRead(cs.TimeoutMs)
	defer r.close()
	for _, dir := range []string{filepath.Dir(paths.directory), paths.directory, filepath.Dir(target)} {
		if _, ok := r.inputs[dir]; ok {
			continue
		}
		if _, err := r.open(dir, true); err != nil {
			return failure()
		}
		if err := trustedDiskInput(r.inputs[dir], uid, gid); err != nil {
			return failure()
		}
	}
	if err := r.expandGroup(paths.directory, "login", "auth", 0); err != nil {
		return failure()
	}
	stack := r.stack
	present, control, noconsole := false, "absent", false
	if len(stack) > 0 && filepath.Base(stack[0].module) == "pam_securetty.so" {
		gate := stack[0]
		if gate.module != "pam_securetty.so" && gate.module != filepath.Join(paths.modules, "pam_securetty.so") && gate.module != strings.Replace(filepath.Join(paths.modules, "pam_securetty.so"), "/usr/lib/", "/lib/", 1) {
			return failure()
		}
		present, control = true, gate.control
		if control != "required" && control != "requisite" && control != "optional" && control != "sufficient" {
			return failure()
		}
		seen := map[string]bool{}
		for _, arg := range gate.args {
			if seen[arg] || arg != "noconsole" && arg != "debug" {
				return failure()
			}
			seen[arg] = true
			noconsole = noconsole || arg == "noconsole"
		}
		stack = stack[1:]
	}
	locked, err := pamAuthTopology(stack, paths.modules)
	if err != nil || locked || len(stack) != 3 || pamAuthUnixArgs(stack[0].args) != nil {
		return failure()
	}
	for _, rule := range r.stack {
		info, err := os.Stat(filepath.Join(paths.modules, filepath.Base(rule.module)))
		if err != nil || !info.Mode().IsRegular() {
			return failure()
		}
	}
	count, allowed, digest := 0, true, "not_observed"
	if present {
		raw, err := boundedDiskInput(r, target)
		if err != nil {
			return failure()
		}
		var lines []string
		if len(raw) > 0 {
			lines = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		}
		if len(lines) > 1024 {
			return failure()
		}
		seen := map[string]bool{}
		for _, line := range lines {
			// Native fgets has a 255-byte buffer and compares literal terminal
			// names; comments and whitespace are not reinterpreted as entries.
			if line == "" {
				return failure()
			}
			if len(line) > 250 || !secureTTYName.MatchString(line) || seen[line] {
				return failure()
			}
			seen[line], count = true, count+1
			allowed = allowed && len(line) == 4 && line[:3] == "tty" && line[3] >= '1' && line[3] <= '6'
		}
		digest = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	for _, input := range r.inputs {
		if trustedDiskInput(input, uid, gid) != nil {
			return failure()
		}
	}
	if r.stable() != nil {
		return failure()
	}
	passed := present && (control == "required" || control == "requisite") && noconsole && count > 0 && allowed
	result := ItemResult{Passed: passed, Actual: fmt.Sprintf("%ssecuretty_present=%t control=%s noconsole=%t tty_count=%d allowed_subset=%t tty_sha256=%s", secureTTYPrefix, present, control, noconsole, count, allowed, digest)}
	if !passed {
		result.Message = "login的首个终端限制、noconsole或非空tty1..tty6子集不满足参考"
	}
	return result
}
