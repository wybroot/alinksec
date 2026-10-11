package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const rescueReference = "rescue+emergency=loaded,sulogin-shell=exact,force_inputs=absent|false"
const rescueForceVariable = "SYSTEMD_SULOGIN_FORCE"

var rescueEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validRescue(cs *CheckSpec) bool {
	return cs.Type == "systemd_rescue_policy" && cs.Target == "local-system" && cs.Operator == "eq" && cs.Expected == rescueReference
}

type rescueQueries struct {
	bus     maintenanceQueries
	cmdline func() (string, error)
}
type rescueUnit struct {
	Properties  map[string]string
	Command     maintenanceCommand
	Flags       []string
	Environment []string
}
type rescueSnapshot struct {
	Manager     map[string]string
	Environment []string
	Cmdline     string
	Units       [2]rescueUnit
}

func rescuePrefix() string {
	return "scope=loaded-systemd-rescue-launch manager=local-system authentication_state=unverified root_account_state=unverified executable_integrity_state=unverified auxiliary_commands_state=unverified execution_namespace_state=unverified boot_paths_state=unverified persistence_state=unverified snapshot_state=non_atomic "
}

func checkSystemdRescue(cs *CheckSpec) ItemResult {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return ItemResult{Error: true, Message: "维护入口启动参考仅支持Linux amd64/arm64 systemd255"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	return observeRescue(ctx, cs, [2]string{"rescue.service", "emergency.service"}, rescueQueries{
		bus: systemMaintenanceQueries(ctx, cs.TimeoutMs),
		cmdline: func() (string, error) {
			f, err := os.Open("/proc/cmdline")
			if err != nil {
				return "", fmt.Errorf("内核启动参数读取失败")
			}
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, 16*1024+1))
			if err != nil || len(b) > 16*1024 || ctx.Err() != nil {
				return "", fmt.Errorf("内核启动参数读取失败、超限或超时")
			}
			return string(b), nil
		},
	})
}

// All query errors and parser errors are redacted: environment and command
// values can contain secrets. Only fixed names, counts and match states escape.
func observeRescue(ctx context.Context, cs *CheckSpec, targets [2]string, q rescueQueries) ItemResult {
	failure := func(err error) ItemResult {
		return ItemResult{Error: true, Actual: rescuePrefix(), Message: err.Error()}
	}
	if !validRescue(cs) {
		return failure(fmt.Errorf("维护入口需固定本地管理器和完整启动参考"))
	}
	var first rescueSnapshot
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			return failure(fmt.Errorf("维护入口超过共同截止时间"))
		}
		s, err := collectRescue(ctx, targets, q)
		if err != nil {
			return failure(err)
		}
		r := evaluateRescue(targets, s)
		if r.Error {
			return r
		}
		if ctx.Err() != nil {
			return failure(fmt.Errorf("维护入口超过共同截止时间"))
		}
		if i == 0 {
			first = s
		} else if !reflect.DeepEqual(first, s) {
			return failure(fmt.Errorf("维护入口属性、命令、环境或启动参数在查询期间变化"))
		}
	}
	return evaluateRescue(targets, first)
}

func rescueStrings(q ItemResult) ([]string, error) {
	raw, err := maintenanceBusData(q, "as")
	if err != nil {
		return nil, fmt.Errorf("维护入口字符串数组查询失败或格式未知")
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || len(entries) > 128 {
		return nil, fmt.Errorf("维护入口字符串数组格式未知或超过128项")
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		var value string
		if len(entry) == 0 || entry[0] != '"' || json.Unmarshal(entry, &value) != nil || len(value) > 4096 || strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("维护入口字符串类型未知或超限")
		}
		result = append(result, value)
	}
	return result, nil
}

// Reuse the existing typed ExecStart ABI validator after replacing the extended
// flags with its boolean field. Preserve the extended flags separately.
func rescueCommand(q ItemResult) (maintenanceCommand, []string, error) {
	var zero maintenanceCommand
	raw, err := maintenanceBusData(q, "a(sasasttttuii)")
	if err != nil {
		return zero, nil, fmt.Errorf("维护入口ExecStartEx查询失败或格式未知")
	}
	var commands [][]json.RawMessage
	if json.Unmarshal(raw, &commands) != nil || len(commands) > 8 {
		return zero, nil, fmt.Errorf("维护入口主命令数组未知或超限")
	}
	var flags []string
	for _, c := range commands {
		if len(c) != 10 {
			return zero, nil, fmt.Errorf("维护入口主命令结构不完整")
		}
		encoded, _ := json.Marshal(map[string]any{"type": "as", "data": c[2]})
		f, err := rescueStrings(ItemResult{Actual: string(encoded)})
		if err != nil || len(f) > 5 {
			return zero, nil, fmt.Errorf("维护入口命令标记格式未知")
		}
		seen := map[string]bool{}
		ignore := false
		for _, flag := range f {
			switch flag {
			case "ignore-failure", "privileged", "no-setuid", "ambient", "no-env-expand":
			default:
				return zero, nil, fmt.Errorf("维护入口命令标记未知")
			}
			if seen[flag] {
				return zero, nil, fmt.Errorf("维护入口命令标记重复")
			}
			seen[flag] = true
			ignore = ignore || flag == "ignore-failure"
		}
		if len(commands) == 1 {
			flags = f
		}
		c[2], _ = json.Marshal(ignore)
	}
	encoded, _ := json.Marshal(map[string]any{"type": "a(sasbttttuii)", "data": commands})
	c, err := parseMaintenanceCommand(ItemResult{Actual: string(encoded)})
	if err != nil {
		return zero, nil, fmt.Errorf("维护入口主命令类型或参数未知")
	}
	c.Digest = fmt.Sprintf("%x", sha256.Sum256(raw))
	return c, flags, nil
}

func collectRescue(ctx context.Context, targets [2]string, q rescueQueries) (rescueSnapshot, error) {
	s := rescueSnapshot{}
	var err error
	s.Manager, err = maintenanceProperties(q.bus.show("Version,SystemState", ""), []string{"Version", "SystemState"}, nil)
	if err != nil {
		return s, fmt.Errorf("维护入口管理器查询失败或格式未知")
	}
	if !ctrlAltDelVersion.MatchString(s.Manager["Version"]) {
		return s, fmt.Errorf("维护入口限定已加载systemd255")
	}
	s.Environment, err = rescueStrings(q.bus.property("", "Manager", "Environment"))
	if err != nil {
		return s, err
	}
	for i, target := range targets {
		if ctx.Err() != nil {
			return s, fmt.Errorf("维护入口超过共同截止时间")
		}
		u := &s.Units[i]
		keys := []string{"Id", "LoadState", "ActiveState", "SubState", "NeedDaemonReload", "Type", "MainPID", "PAMName", "RootDirectory", "RootImage"}
		u.Properties, err = maintenanceProperties(q.bus.show(strings.Join(keys, ","), target), keys, []string{"PAMName", "RootDirectory", "RootImage"})
		if err != nil {
			return s, fmt.Errorf("维护入口单元查询失败或格式未知")
		}
		u.Command, u.Flags, err = rescueCommand(q.bus.property(target, "Service", "ExecStartEx"))
		if err != nil {
			return s, err
		}
		u.Environment, err = rescueStrings(q.bus.property(target, "Service", "Environment"))
		if err != nil {
			return s, err
		}
		for _, name := range []string{"PassEnvironment", "UnsetEnvironment"} {
			entries, err := rescueStrings(q.bus.property(target, "Service", name))
			if err != nil {
				return s, err
			}
			if len(entries) != 0 {
				return s, fmt.Errorf("维护入口额外环境传递或移除链尚未支持")
			}
		}
		raw, err := maintenanceBusData(q.bus.property(target, "Service", "EnvironmentFiles"), "a(sb)")
		var files []json.RawMessage
		if err != nil || json.Unmarshal(raw, &files) != nil || len(files) != 0 {
			return s, fmt.Errorf("维护入口环境文件链非空或无法确认；不读取环境文件")
		}
	}
	s.Cmdline, err = q.cmdline()
	if err != nil {
		return s, fmt.Errorf("维护入口内核启动参数读取失败、超限或超时")
	}
	return s, nil
}

func rescueBool(value string) (string, error) {
	switch strings.ToLower(value) {
	case "0", "no", "false", "off":
		return "false", nil
	case "1", "yes", "true", "on":
		return "true", nil
	default:
		return "", fmt.Errorf("维护入口force布尔声明未知")
	}
}
func rescueEnvironment(entries []string) (string, error) {
	force := "absent"
	seen := map[string]bool{}
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !rescueEnvironmentName.MatchString(key) || seen[key] {
			return "", fmt.Errorf("维护入口环境声明未知或重复")
		}
		seen[key] = true
		if key == rescueForceVariable {
			var err error
			force, err = rescueBool(value)
			if err != nil {
				return "", err
			}
		}
	}
	return force, nil
}
func rescueCmdline(raw string) (string, error) {
	if raw == "" || len(raw) > 16*1024 {
		return "", fmt.Errorf("维护入口启动参数为空或超限")
	}
	for _, c := range []byte(raw) {
		if c != '\n' && c != '\t' && c != ' ' && (c < 0x21 || c > 0x7e) || c == '\'' || c == '"' || c == '\\' {
			return "", fmt.Errorf("维护入口启动参数引号、转义或语法尚未支持")
		}
	}
	force := "absent"
	fields := strings.Fields(raw)
	if len(fields) == 0 || len(fields) > 1024 {
		return "", fmt.Errorf("维护入口启动参数数量无效或超限")
	}
	for _, field := range fields {
		if field == "--" {
			return "", fmt.Errorf("维护入口启动参数分隔语义尚未支持")
		}
		key, value, assigned := strings.Cut(field, "=")
		// proc_cmdline_key_streq treats hyphens and underscores equally.
		key = strings.ReplaceAll(key, "-", "_")
		if key == "rd."+rescueForceVariable {
			return "", fmt.Errorf("维护入口initrd force声明尚未支持")
		}
		if key == rescueForceVariable {
			if force != "absent" {
				return "", fmt.Errorf("维护入口启动force声明重复")
			}
			if !assigned {
				force = "true"
			} else {
				var err error
				force, err = rescueBool(value)
				if err != nil {
					return "", err
				}
			}
		}
	}
	return force, nil
}

func evaluateRescue(targets [2]string, s rescueSnapshot) ItemResult {
	failure := func(err error) ItemResult {
		return ItemResult{Error: true, Actual: rescuePrefix(), Message: err.Error()}
	}
	if !ctrlAltDelVersion.MatchString(s.Manager["Version"]) {
		return failure(fmt.Errorf("维护入口限定systemd255"))
	}
	switch s.Manager["SystemState"] {
	case "running", "degraded", "maintenance":
	default:
		return failure(fmt.Errorf("维护入口管理器切换中或未知"))
	}
	manager, err := rescueEnvironment(s.Environment)
	if err != nil {
		return failure(err)
	}
	kernel, err := rescueCmdline(s.Cmdline)
	if err != nil {
		return failure(err)
	}
	passed := manager != "true" && kernel != "true"
	actual := fmt.Sprintf("%sVersion=%s SystemState=%s manager_force=%s kernel_force=%s", rescuePrefix(), s.Manager["Version"], s.Manager["SystemState"], manager, kernel)
	for i, target := range targets {
		u := s.Units[i]
		if err := maintenanceBase(u.Properties, target, false); err != nil {
			return failure(fmt.Errorf("维护入口单元身份、加载、重载或稳定状态无法确认"))
		}
		pid, err := strconv.ParseUint(u.Properties["MainPID"], 10, 32)
		if err != nil || strconv.FormatUint(pid, 10) != u.Properties["MainPID"] || u.Properties["ActiveState"] == "active" && u.Properties["SubState"] == "running" && pid <= 1 {
			return failure(fmt.Errorf("维护入口主进程属性不完整或未知"))
		}
		if u.Properties["PAMName"] != "" || u.Properties["RootDirectory"] != "" || u.Properties["RootImage"] != "" {
			return failure(fmt.Errorf("维护入口PAM或替代根链尚未支持"))
		}
		switch u.Properties["Type"] {
		case "simple", "exec", "forking", "oneshot", "dbus", "notify", "notify-reload", "idle":
		default:
			return failure(fmt.Errorf("维护入口服务类型未知"))
		}
		unitForce, err := rescueEnvironment(u.Environment)
		if err != nil {
			return failure(err)
		}
		path := "/usr/lib/systemd/systemd-sulogin-shell"
		mode := []string{"rescue", "emergency"}[i]
		command := u.Command.Path == path && len(u.Command.Argv) == 2 && (u.Command.Argv[0] == path || u.Command.Argv[0] == "systemd-sulogin-shell") && u.Command.Argv[1] == mode
		flags := len(u.Flags) == 0 || len(u.Flags) == 1 && u.Flags[0] == "ignore-failure"
		passed = passed && u.Properties["LoadState"] == "loaded" && u.Properties["Type"] == "idle" && command && flags && unitForce != "true"
		actual += fmt.Sprintf(" %s:LoadState=%s,ActiveState=%s,SubState=%s,Type=%s,command_reference_match=%t,flags_reference_match=%t,unit_force=%s", mode, u.Properties["LoadState"], u.Properties["ActiveState"], u.Properties["SubState"], u.Properties["Type"], command, flags, unitForce)
	}
	message := ""
	if !passed {
		message = "维护入口主命令或force输入未满足完整启动声明参考；实际认证未验证"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
