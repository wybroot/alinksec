//go:build linux

package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type pamAuthPaths struct{ directory, policy, modules string }
type faillockSettings struct {
	deny, interval, unlock, rootUnlock int
	root, localOnly                    bool
	directory                          string
}

func systemPAMAuthPaths() pamAuthPaths {
	p := systemPAMPaths()
	return pamAuthPaths{p.directory, "/etc/security/faillock.conf", p.modules}
}

// Accept only the fixed shared tally path and explicit, bounded settings.
// Native scanf overflow/trailing junk and unknown options are not guessed.
func (s *faillockSettings) apply(key, value string) error {
	switch key {
	case "deny", "fail_interval", "unlock_time", "root_unlock_time":
		if value == "never" && (key == "unlock_time" || key == "root_unlock_time") {
			value = "0"
		}
		if value == "" || strings.ContainsFunc(value, func(c rune) bool { return c < '0' || c > '9' }) {
			return fmt.Errorf("faillock 整数格式无效")
		}
		n, err := strconv.ParseUint(value, 10, 32)
		limit := uint64(604800)
		if key == "deny" {
			limit = 65535
		}
		if err != nil || n > limit {
			return fmt.Errorf("faillock 整数超过原生范围")
		}
		switch key {
		case "deny":
			s.deny = int(n)
		case "fail_interval":
			s.interval = int(n)
		case "unlock_time":
			s.unlock = int(n)
		case "root_unlock_time":
			s.rootUnlock = int(n)
		}
	case "even_deny_root":
		s.root = true // Native SET flag, including '=0'.
	case "local_users_only":
		s.localOnly = true
	case "silent", "audit", "no_log_info", "nodelay": // Native SET flags; no effect on this reference.
	case "dir":
		if value != "/run/faillock" && value != "/var/run/faillock" {
			return fmt.Errorf("faillock 计数目录尚未支持")
		}
		s.directory = value
	default:
		return fmt.Errorf("faillock 配置项尚未支持")
	}
	return nil
}

func readFaillockSettings(r *pamRead, path string) (faillockSettings, error) {
	s := faillockSettings{deny: 3, interval: 900, unlock: 600, rootUnlock: -1, directory: "/var/run/faillock"}
	lines, err := r.lines(path)
	if err != nil {
		return s, err
	}
	for _, line := range lines {
		if len(line) >= 1023 {
			return s, fmt.Errorf("faillock 行超过原生解析长度")
		}
		if at := strings.IndexByte(line, '#'); at >= 0 {
			line = line[:at]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		at := strings.IndexAny(line, "= \t\r")
		key, value := line, ""
		if at >= 0 {
			key, value = line[:at], strings.TrimSpace(line[at:])
			value = strings.TrimSpace(strings.TrimPrefix(value, "="))
		}
		if err := s.apply(key, value); err != nil {
			return s, err
		}
	}
	return s, nil
}

func faillockStage(base faillockSettings, args []string, action string) (faillockSettings, error) {
	seen := map[string]bool{}
	selected := ""
	for _, arg := range args {
		key, value, _ := strings.Cut(arg, "=")
		if seen[key] || len(arg) >= 1023 {
			return base, fmt.Errorf("faillock 模块参数重复或超限")
		}
		seen[key] = true
		if arg == "preauth" || arg == "authfail" || arg == "authsucc" {
			if selected != "" {
				return base, fmt.Errorf("faillock 阶段冲突")
			}
			selected = arg
		} else if arg == "conf=/etc/security/faillock.conf" {
			// The same fixed config, not a caller-selected path.
		} else if err := base.apply(key, value); err != nil {
			return base, err
		}
	}
	if selected != action {
		return base, fmt.Errorf("faillock 阶段缺失或顺序无效")
	}
	if base.localOnly {
		return base, fmt.Errorf("faillock local_users_only 的身份分支尚未支持")
	}
	if base.rootUnlock == -1 {
		base.rootUnlock = base.unlock
	}
	return base, nil
}

func pamAuthTopology(stack []pamRule, dir string) (bool, error) {
	for i := range stack {
		name := filepath.Base(stack[i].module)
		if name == "pam_faillock.so" {
			if stack[i].module != name && stack[i].module != filepath.Join(dir, name) && stack[i].module != strings.Replace(filepath.Join(dir, name), "/usr/lib/", "/lib/", 1) {
				return false, fmt.Errorf("PAM 模块路径尚未支持")
			}
		} else if _, err := pamModuleName(stack[i].module, dir); err != nil {
			return false, err
		}
		stack[i].module = name
	}
	// A fully understood local unix/deny/permit chain without lockout is a
	// policy failure. Any other partial/unknown chain remains unconfirmed.
	if len(stack) == 3 && stack[0].module == "pam_unix.so" && stack[0].control == "[default=ignore success=1]" && stack[1].module == "pam_deny.so" && stack[1].control == "requisite" && len(stack[1].args) == 0 && stack[2].module == "pam_permit.so" && stack[2].control == "required" && len(stack[2].args) == 0 {
		return false, nil
	}
	modules := []string{"pam_faillock.so", "pam_unix.so", "pam_faillock.so", "pam_faillock.so", "pam_deny.so"}
	controls := []string{"required", "[default=bad success=1]", "[default=die]", "sufficient", "required"}
	if len(stack) != len(modules) {
		return false, fmt.Errorf("PAM auth 链尚未支持")
	}
	for i := range stack {
		if stack[i].module != modules[i] || stack[i].control != controls[i] {
			return false, fmt.Errorf("PAM auth 模块顺序或控制尚未支持")
		}
	}
	if len(stack[4].args) != 0 {
		return false, fmt.Errorf("pam_deny 参数尚未支持")
	}
	return true, nil
}

func pamAuthUnixArgs(args []string) error {
	seen := map[string]bool{}
	for _, arg := range args {
		if seen[arg] {
			return fmt.Errorf("pam_unix 认证参数重复")
		}
		seen[arg] = true
		switch arg {
		case "try_first_pass", "use_first_pass", "nullok", "nodelay":
		default:
			return fmt.Errorf("pam_unix 认证参数尚未支持")
		}
	}
	return nil
}

func checkPAMAuth(cs *CheckSpec) ItemResult { return pamAuthWithin(cs, systemPAMAuthPaths()) }
func pamAuthWithin(cs *CheckSpec, paths pamAuthPaths) ItemResult {
	r := newPAMRead(cs.TimeoutMs)
	defer r.close()
	prefix := "scope=login-auth-chain service=/etc/pam.d/login "
	failure := func(err error) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: err.Error()} }
	if _, err := r.open(paths.directory, true); err != nil {
		return failure(err)
	}
	if err := r.expandGroup(paths.directory, "login", "auth", 0); err != nil {
		return failure(err)
	}
	locked, err := pamAuthTopology(r.stack, paths.modules)
	if err != nil {
		return failure(err)
	}
	unixIndex := 0
	if locked {
		unixIndex = 1
	}
	if err := pamAuthUnixArgs(r.stack[unixIndex].args); err != nil {
		return failure(err)
	}
	for _, rule := range r.stack {
		info, err := os.Stat(filepath.Join(paths.modules, rule.module))
		if err != nil || !info.Mode().IsRegular() {
			return failure(fmt.Errorf("PAM 所需模块文件缺失或非普通文件"))
		}
	}
	if !locked {
		if err := r.stable(); err != nil {
			return failure(err)
		}
		return ItemResult{Actual: prefix + "stack=local-unix-deny-permit faillock_present=false", Message: "已支持的 login auth 链未包含失败锁定"}
	}
	base, err := readFaillockSettings(r, paths.policy)
	if err != nil {
		return failure(err)
	}
	var stages []faillockSettings
	for i, action := range []string{"preauth", "authfail", "authsucc"} {
		index := []int{0, 2, 3}[i]
		settings, err := faillockStage(base, r.stack[index].args, action)
		if err != nil {
			return failure(err)
		}
		stages = append(stages, settings)
	}
	if stages[0] != stages[1] || stages[1] != stages[2] {
		return failure(fmt.Errorf("faillock 三阶段计数策略不一致，无法确认锁定"))
	}
	if err := r.stable(); err != nil {
		return failure(err)
	}
	s := stages[0]
	actual := fmt.Sprintf("%sstack=preauth-unix-authfail-authsucc-deny deny=%d fail_interval=%d unlock_time=%d explicit_even_deny_root=%t root_unlock_time=%d tally_dir=%s inputs=%d", prefix, s.deny, s.interval, s.unlock, s.root, s.rootUnlock, s.directory, len(r.inputs))
	passed := s.deny >= 1 && s.deny <= 5 && s.interval >= 900 && s.unlock >= 900 && s.unlock <= 86400 && s.root && s.rootUnlock >= 900 && s.rootUnlock <= 86400
	result := ItemResult{Passed: passed, Actual: actual}
	if !passed {
		result.Message = "登录失败次数、观察窗口、有限解锁时间或显式 root 锁定不满足参考"
	}
	return result
}
