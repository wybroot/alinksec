//go:build linux

package baseline

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type pamLimitsPaths struct {
	directory, security, modules string
	uid, gid                     uint32 // fixed root:root in production; fixture identity in unit tests
}
type pamLimitPair struct{ soft, hard string }
type pamLimitsPolicy map[string]map[string]pamLimitPair

var pamLimitsVersion = regexp.MustCompile(`^1\.5\.3-5ubuntu5(\.[0-9]+)?$`)

func systemPAMLimitsPaths() pamLimitsPaths {
	p := systemPAMPaths()
	return pamLimitsPaths{directory: p.directory, security: "/etc/security", modules: p.modules}
}

func checkPAMLimits(cs *CheckSpec) ItemResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${Version}", "libpam-modules")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	query := collectBaselineCommand(ctx, cmd, cs.TimeoutMs)
	if query.Error || !pamLimitsVersion.MatchString(query.Actual) {
		return ItemResult{Error: true, Message: "pam_limits 需可查询的 Ubuntu24 libpam-modules 1.5.3-5ubuntu5 系列"}
	}
	deadline, _ := ctx.Deadline()
	result := pamLimitsWithin(cs, systemPAMLimitsPaths(), deadline)
	result.Actual = "package_version=" + query.Actual + " " + result.Actual
	return result
}

// This is a disk declaration and finite session-chain observation. It never
// opens a production PAM session, changes this process's rlimits, or infers the
// limits of existing sessions. Native probes belong to the disposable fixture.
func pamLimitsWithin(cs *CheckSpec, paths pamLimitsPaths, deadline time.Time) ItemResult {
	prefix := "scope=login-pam-limits-declarations service=login option=" + cs.Option +
		" invocation_state=unverified existing_process_state=unverified core_delivery_state=unverified nproc_privileged_enforcement_state=unverified "
	failure := func(err error) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: err.Error()} }
	if !validPAMLimits(cs) {
		return failure(fmt.Errorf("PAM limits 需固定 login 入口与完整参考"))
	}
	r := newPAMRead(cs.TimeoutMs)
	r.deadline = deadline
	defer r.close()
	for _, dir := range []string{filepath.Dir(paths.directory), paths.directory, paths.security} {
		if _, err := r.open(dir, true); err != nil {
			return failure(err)
		}
	}
	if err := r.expandGroup(paths.directory, "login", "session", 0); err != nil {
		return failure(err)
	}
	present, err := pamLimitsTopology(r.stack, paths.modules)
	if err != nil {
		return failure(err)
	}
	for _, rule := range r.stack {
		info, err := os.Lstat(filepath.Join(paths.modules, filepath.Base(rule.module)))
		if err != nil || !info.Mode().IsRegular() {
			return failure(fmt.Errorf("PAM session 模块缺失或不是固定普通文件"))
		}
	}
	policy, err := readPAMLimitsPolicy(r, paths.security)
	if err != nil {
		return failure(err)
	}
	// Require trustworthy policy inputs without relaxing the older PAM checks.
	for _, input := range r.inputs {
		stat := input.info.Sys().(*syscall.Stat_t)
		if stat.Uid != paths.uid || stat.Gid != paths.gid || stat.Mode&0022 != 0 || input.info.Mode().IsRegular() && stat.Nlink != 1 {
			return failure(fmt.Errorf("PAM limits 配置需root:root且不能组/其他可写或有硬链接"))
		}
	}
	if err := r.stable(); err != nil {
		return failure(err)
	}
	actual := fmt.Sprintf("%srequired_limits_present=%t inputs=%d", prefix, present, len(r.inputs))
	passed := present
	for _, domain := range []string{"*", "root"} {
		pair := policy[domain][cs.Option]
		if pair.soft == "unlimited" || pair.hard == "unlimited" {
			passed = false // reference requires explicit finite declarations
		}
		soft, hard := pair.soft, pair.hard
		// Native setup_limits clamps a configured soft value to the hard value.
		// Missing declarations stay unspecified: inherited limits are unobserved.
		if soft != "" && hard != "" {
			if hard != "unlimited" && (soft == "unlimited" || limitNumber(soft) > limitNumber(hard)) {
				soft = hard
			}
		}
		name := "default"
		if domain == "root" {
			name = "explicit_root"
		}
		show := func(value string) string {
			if value == "" {
				return "unspecified"
			}
			return value
		}
		actual += fmt.Sprintf(" %s_declared_soft=%s %s_declared_hard=%s %s_normalized_soft=%s",
			name, show(pair.soft), name, show(pair.hard), name, show(soft))
		min, max := uint64(0), uint64(0)
		switch cs.Option {
		case "nofile":
			min, max = 1024, 65536
		case "nproc":
			min, max = 1, 4096
		}
		for _, value := range []string{soft, hard} {
			if value == "" || value == "unlimited" || limitNumber(value) < min || limitNumber(value) > max {
				passed = false
			}
		}
	}
	message := ""
	if !passed {
		message = "login session 强制limits或默认/显式root soft和hard声明未满足参考；实际会话与现存进程未验证"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}

func limitNumber(value string) uint64 { n, _ := strconv.ParseUint(value, 10, 64); return n }

// No jumps, sufficient shortcuts, optional limits, or later modules that can
// reset resource limits. Missing limits in an otherwise known chain is a fail.
func pamLimitsTopology(stack []pamRule, dir string) (bool, error) {
	present := false
	for _, rule := range stack {
		name := filepath.Base(rule.module)
		if rule.module != name && rule.module != filepath.Join(dir, name) && rule.module != strings.Replace(filepath.Join(dir, name), "/usr/lib/", "/lib/", 1) {
			return false, fmt.Errorf("PAM session 模块路径尚未支持")
		}
		if rule.control != "required" || len(rule.args) != 0 {
			return false, fmt.Errorf("PAM session 仅支持无参数required模块；跳转/可选/参数保持未确认")
		}
		switch name {
		case "pam_limits.so":
			if present {
				return false, fmt.Errorf("重复pam_limits模块尚未支持")
			}
			present = true
		case "pam_unix.so", "pam_permit.so":
		default:
			return false, fmt.Errorf("PAM session 模块尚未支持")
		}
	}
	return present, nil
}

func readPAMLimitsPolicy(r *pamRead, security string) (pamLimitsPolicy, error) {
	policy := pamLimitsPolicy{"*": {}, "root": {}}
	parse := func(path string) error {
		lines, err := r.lines(path)
		if err != nil {
			return err
		}
		for _, raw := range lines {
			// Linux-PAM 1.5.3 uses fgets(..., LINE_LENGTH=1024).
			if len(raw) >= 1023 {
				return fmt.Errorf("limits配置行超过原生读取边界")
			}
			line, _, _ := strings.Cut(raw, "#")
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			if len(parts) != 4 || (parts[0] != "*" && parts[0] != "root") {
				return fmt.Errorf("limits仅支持默认*和显式root完整声明；账户/组/范围/豁免尚未支持")
			}
			domain, kind, item, value := parts[0], strings.ToLower(parts[1]), strings.ToLower(parts[2]), strings.ToLower(parts[3])
			if (kind != "soft" && kind != "hard" && kind != "-") || (item != "core" && item != "nofile" && item != "nproc") {
				return fmt.Errorf("limits类型或资源尚未支持")
			}
			if value == "-1" || value == "infinity" || value == "unlimited" {
				// nofile infinity becomes nr_open in PAM. This deliberately fails
				// the explicit finite declaration reference without guessing it.
				value = "unlimited"
			} else {
				n, err := strconv.ParseUint(value, 10, 64)
				if err != nil || value == "" || strings.ContainsFunc(value, func(c rune) bool { return c < '0' || c > '9' }) || n > 2147483647 {
					return fmt.Errorf("limits值不是有界完整非负整数")
				}
				value = strconv.FormatUint(n, 10)
			}
			pair := policy[domain][item]
			if kind == "soft" || kind == "-" {
				pair.soft = value
			}
			if kind == "hard" || kind == "-" {
				pair.hard = value
			}
			policy[domain][item] = pair
		}
		return nil
	}
	if err := parse(filepath.Join(security, "limits.conf")); err != nil {
		return nil, err
	}
	dir := filepath.Join(security, "limits.d")
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		r.absent = append(r.absent, dir)
		return policy, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("limits.d需非链接目录")
	}
	f, err := r.open(dir, true)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(129)
	if err != nil && err != io.EOF || len(names) > 128 {
		return nil, fmt.Errorf("limits.d枚举失败或条目超限")
	}
	sort.Strings(names)
	count := 0
	for _, name := range names {
		// glob *.conf excludes leading-dot files, includes ordinary backup
		// names ending .conf, and selects directories/symlinks (then reject).
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		count++
		if count > 64 {
			return nil, fmt.Errorf("limits.d配置文件超过64个")
		}
		if err := parse(filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	return policy, r.budget()
}
