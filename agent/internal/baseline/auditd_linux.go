//go:build linux

package baseline

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// This describes the fixed ON-DISK configuration, never a daemon's loaded
// configuration. Do not invoke auditd, resolve NSS names, or read log contents.
func checkAuditdConfig(cs *CheckSpec) ItemResult { return auditdConfigWithin(cs, "/") }

var auditdNumber = regexp.MustCompile(`^[0-9]+$`)

// A deliberately bounded subset of auditd 3.1.2. Unsupported keys/actions are
// errors, including exec scripts, remote transports and custom dispatchers.
var auditdEnums = map[string]string{
	"local_events": "yes|no", "write_logs": "yes|no", "log_format": "raw|enriched|nolog",
	"flush":                   "none|incremental|incremental_async|data|sync",
	"max_log_file_action":     "ignore|syslog|suspend|rotate|keep_logs",
	"space_left_action":       "ignore|syslog|rotate|email|suspend|single|halt",
	"admin_space_left_action": "ignore|syslog|rotate|email|suspend|single|halt",
	"disk_full_action":        "ignore|syslog|rotate|email|suspend|single|halt",
	"disk_error_action":       "ignore|syslog|rotate|email|suspend|single|halt",
	"overflow_action":         "ignore|syslog|suspend|single|halt",
	"verify_email":            "yes|no", "name_format": "none", "distribute_network": "yes|no",
}
var auditdNumbers = map[string]uint64{
	"freq": 2147483647, "num_logs": 999, "max_log_file": 1<<63 - 1,
	"space_left": 1<<63 - 1, "admin_space_left": 1<<63 - 1,
	"priority_boost": 2147483647, "q_depth": 99999, "max_restarts": 2147483647,
	"end_of_event_timeout": 1<<63 - 1,
}

func auditdLogPath(value string) bool {
	// Restrict metadata discovery to ordinary local log paths, never arbitrary
	// candidate paths, credentials, devices or another filesystem root.
	return strings.HasPrefix(value, "/var/log/") && len(value) <= 128 &&
		filepath.Clean(value) == value && value != "/var/log/" &&
		regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`).MatchString(value)
}

func parseAuditdConfig(raw string) (map[string]string, error) {
	bad := func() (map[string]string, error) {
		return nil, fmt.Errorf("auditd 配置语法、字段或值未支持；需无歧义的 3.1.2 本地配置")
	}
	if len(raw) == 0 || len(raw) > 64*1024 || !strings.HasSuffix(raw, "\n") {
		return bad()
	}
	values := map[string]string{"local_events": "yes", "write_logs": "yes", "log_format": "enriched",
		"log_file": "/var/log/audit/audit.log", "log_group": "0", "max_log_file": "0",
		"max_log_file_action": "ignore", "flush": "none", "freq": "0", "space_left": "0", "admin_space_left": "0"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		// fgets(buf[160]) skips longer lines and an unterminated final line.
		// Refuse those inputs instead of silently inspecting a different policy.
		if len(line) > 158 {
			return bad()
		}
		for _, b := range []byte(line) {
			if b < 32 || b > 126 {
				return bad()
			}
		}
		line = strings.Trim(line, " ")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 || parts[1] != "=" {
			return bad()
		}
		key, value := strings.ToLower(parts[0]), parts[2]
		if seen[key] {
			return bad()
		}
		seen[key] = true
		if choices, ok := auditdEnums[key]; ok {
			value = strings.ToLower(value)
			if !slices.Contains(strings.Split(choices, "|"), value) {
				return bad()
			}
		} else if max, ok := auditdNumbers[key]; ok {
			n, err := strconv.ParseUint(value, 10, 64)
			if !auditdNumber.MatchString(value) || err != nil || n > max {
				return bad()
			}
			value = strconv.FormatUint(n, 10)
		} else {
			switch key {
			case "log_file":
				if !auditdLogPath(value) {
					return bad()
				}
			case "log_group":
				// root is common in the vendor file. It can be observed as a
				// declaration, but metadata cannot infer its NSS-resolved GID.
				if value != "root" {
					n, err := strconv.ParseUint(value, 10, 32)
					if !auditdNumber.MatchString(value) || err != nil || n == 1<<32-1 {
						return bad()
					}
					value = strconv.FormatUint(n, 10)
				}
			case "action_mail_acct":
				if value != "root" {
					return bad()
				}
			case "plugin_dir":
				if value != "/etc/audit/plugins.d" && value != "/etc/audit/plugins.d/" {
					return bad()
				}
			default:
				return bad()
			}
		}
		values[key] = value
		// NOLOG changes write_logs at this point in the native parser. A later
		// explicit write_logs may override it, but NOLOG still fails our policy.
		if key == "log_format" && value == "nolog" {
			values["write_logs"] = "no"
		}
	}
	space, _ := strconv.ParseUint(values["space_left"], 10, 64)
	admin, _ := strconv.ParseUint(values["admin_space_left"], 10, 64)
	if space <= admin || (values["flush"] == "incremental" || values["flush"] == "incremental_async") && values["freq"] == "0" {
		return bad()
	}
	if values["log_group"] != "0" && filepath.Dir(values["log_file"]) == "/var/log" {
		return bad()
	}
	return values, nil
}

type auditdInput struct {
	file         *os.File
	stat         *syscall.Stat_t
	parents      []unix.Stat_t
	root, target string
}

func openAuditdInput(root, target string) (*auditdInput, error) {
	f, parents, err := openLogPath(root, target)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("auditd 输入需普通无链接文件")
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("auditd 输入存在硬链接或正在被替换")
	}
	size, aclErr := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), "system.posix_acl_access", nil)
	if aclErr != nil && aclErr != unix.ENODATA || size > 0 {
		f.Close()
		return nil, fmt.Errorf("auditd 输入存在访问 ACL 或无法确认 ACL")
	}
	return &auditdInput{f, st, parents, root, target}, nil
}

func (in *auditdInput) stable(contents bool) bool {
	current, parents, err := openLogPath(in.root, in.target)
	if err != nil {
		return false
	}
	defer current.Close()
	now, err := current.Stat()
	after, afterErr := in.file.Stat()
	if err != nil || afterErr != nil || len(parents) != len(in.parents) {
		return false
	}
	a, b := after.Sys().(*syscall.Stat_t), now.Sys().(*syscall.Stat_t)
	if !sameLogMetadata(in.stat, a) || !sameLogMetadata(in.stat, b) || contents && (in.stat.Size != a.Size || in.stat.Mtim != a.Mtim) {
		return false
	}
	for i := range parents {
		if parents[i].Dev != in.parents[i].Dev || parents[i].Ino != in.parents[i].Ino {
			return false
		}
	}
	return true
}

func auditdConfigWithin(cs *CheckSpec, root string) ItemResult {
	actual := "scope=on-disk-auditd-3.1.2 config=/etc/audit/auditd.conf option=" + cs.Option + " loaded_state=unverified"
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: actual, Message: message} }
	if cs.Target != "/etc/audit/auditd.conf" || cs.Operator != "eq" || auditdReference(cs.Option) == "" || cs.Expected != auditdReference(cs.Option) {
		return failure("auditd 参考定义无效")
	}
	deadline := time.Now().Add(time.Duration(cs.TimeoutMs) * time.Millisecond)
	config, err := openAuditdInput(root, cs.Target)
	if err != nil {
		return failure(err.Error())
	}
	defer config.file.Close()
	if config.stat.Size > 64*1024 || config.stat.Uid != 0 || config.stat.Mode&0022 != 0 {
		return failure("auditd 配置需有界 UID 0 普通文件，且不得由组或其他用户写入")
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", config.file.Fd()), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return failure("无法读取固定 auditd 配置")
	}
	reader := os.NewFile(uintptr(fd), cs.Target)
	raw, err := io.ReadAll(io.LimitReader(reader, 64*1024+1))
	reader.Close()
	if err != nil || time.Now().After(deadline) {
		return failure("auditd 配置读取异常或超时")
	}
	values, err := parseAuditdConfig(string(raw))
	if err != nil {
		return failure(err.Error())
	}
	actual += fmt.Sprintf(" local_events=%s write_logs=%s log_format=%s", values["local_events"], values["write_logs"], values["log_format"])
	passed := values["local_events"] == "yes" && values["write_logs"] == "yes" && values["log_format"] != "nolog"
	var target *auditdInput
	switch cs.Option {
	case "keep_logs":
		actual += " max_log_file=" + values["max_log_file"] + " max_log_file_action=" + values["max_log_file_action"]
		passed = passed && values["max_log_file"] != "0" && values["max_log_file_action"] == "keep_logs"
	case "log_file_metadata":
		actual += " log_file=" + values["log_file"] + " log_group=" + values["log_group"]
		if values["log_group"] == "root" {
			return failure("命名 log_group 需 NSS 解析；本元数据参考仅支持明确数值 GID")
		}
		target, err = openAuditdInput(root, values["log_file"])
		if err != nil {
			return failure(err.Error())
		}
		defer target.file.Close()
		st := target.stat
		gid, _ := strconv.ParseUint(values["log_group"], 10, 32)
		actual += fmt.Sprintf(" kind=regular mode=%04o uid=%d gid=%d access_acl=none allowed_mode=0640 expected_uid=0 expected_gid=%d", st.Mode&07777, st.Uid, st.Gid, gid)
		passed = passed && st.Mode&07777 & ^uint32(0640) == 0 && st.Uid == 0 && st.Gid == uint32(gid)
	}
	if !config.stable(true) || target != nil && !target.stable(false) || time.Now().After(deadline) {
		return failure("auditd 配置/日志路径或元数据变化，或超过共享截止时间，请重试")
	}
	message := ""
	if !passed {
		message = "磁盘声明或已观察日志元数据不满足参考；未确认运行实例加载、写入、交付或保留期限"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
