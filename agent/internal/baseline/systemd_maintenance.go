package baseline

import (
	"context"
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var maintenanceReferences = map[string]string{
	"tmpfiles_clean": "timer=loaded/active/waiting,next_monotonic=finite_positive,service=loaded/oneshot,inactive/dead,remain=no,command=systemd-tmpfiles--clean",
	"time_sync":      "service=loaded/active/running,type=notify,command=systemd-timesyncd,kernel_state=0..4,STA_UNSYNC=0,STA_CLOCKERR=0",
}

const maintenanceBaseProperties = "Id,LoadState,ActiveState,SubState,NeedDaemonReload"

var maintenanceUnitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\.(service|timer)$`)

type maintenanceTargets struct{ timer, cleaner, sync string }

func systemMaintenanceTargets() maintenanceTargets {
	return maintenanceTargets{"systemd-tmpfiles-clean.timer", "systemd-tmpfiles-clean.service", "systemd-timesyncd.service"}
}
func validMaintenance(cs *CheckSpec) bool {
	return cs.Type == "systemd_maintenance" && cs.Target == "local-system" && cs.Operator == "eq" && maintenanceReferences[cs.Option] != "" && cs.Expected == maintenanceReferences[cs.Option]
}

type kernelClockSample struct {
	State              int
	Status             uint32
	MaxError, EstError int64
}
type maintenanceSnapshot struct {
	Manager, Service, Timer map[string]string
	Command                 maintenanceCommand
	Next                    uint64
	Clock                   kernelClockSample
}
type maintenanceQueries struct {
	show     func(string, string) ItemResult
	property func(string, string, string) ItemResult
	clock    func() (kernelClockSample, error)
}

func maintenancePrefix(option string) string {
	return "scope=loaded-systemd-maintenance option=" + option + " manager=local-system cleanup_configuration_state=unverified cleanup_delivery_state=unverified ntp_provider_state=unverified peer_identity_state=unverified offset_accuracy_state=unverified execution_environment_state=unverified persistence_state=unverified snapshot_state=non_atomic "
}
func checkSystemdMaintenance(cs *CheckSpec) ItemResult {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return ItemResult{Error: true, Message: "systemd维护参考仅支持Linux amd64/arm64"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	return observeMaintenance(ctx, cs, systemMaintenanceTargets(), systemMaintenanceQueries(ctx, cs.TimeoutMs))
}
func systemMaintenanceQueries(ctx context.Context, timeout int) maintenanceQueries {
	command := func(path string, args ...string) ItemResult {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
		return collectBaselineCommand(ctx, cmd, timeout)
	}
	return maintenanceQueries{
		show: func(properties, target string) ItemResult {
			args := []string{"--system", "--no-pager", "show", "--all", "--property=" + properties}
			if target != "" {
				args = append(args, "--", target)
			}
			return command("/usr/bin/systemctl", args...)
		},
		property: func(target, iface, property string) ItemResult {
			if !maintenanceUnitName.MatchString(target) {
				return ItemResult{Error: true, Message: "invalid fixed unit"}
			}
			var path strings.Builder
			path.WriteString("/org/freedesktop/systemd1/unit/")
			for _, c := range []byte(target) {
				if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
					path.WriteByte(c)
				} else {
					fmt.Fprintf(&path, "_%02x", c)
				}
			}
			return command("/usr/bin/busctl", "--system", "--no-pager", "--json=short", "get-property", "org.freedesktop.systemd1", path.String(), "org.freedesktop.systemd1."+iface, property)
		},
		clock: readKernelClock,
	}
}
func maintenanceProperties(q ItemResult, keys, empty []string) (map[string]string, error) {
	if q.Error {
		return nil, fmt.Errorf("systemd维护查询失败、超限或超时")
	}
	allowed, empties := map[string]bool{}, map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for _, key := range empty {
		empties[key] = true
	}
	values := map[string]string{}
	for _, line := range strings.Split(q.Actual, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] || strings.TrimSpace(value) != value || value == "" && !empties[key] || strings.ContainsAny(value, "\x00\r") {
			return nil, fmt.Errorf("systemd维护属性未知、为空或格式无效")
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("systemd维护属性重复")
		}
		values[key] = value
	}
	if len(values) != len(keys) {
		return nil, fmt.Errorf("systemd维护属性不完整")
	}
	return values, nil
}
func observeMaintenance(ctx context.Context, cs *CheckSpec, targets maintenanceTargets, q maintenanceQueries) ItemResult {
	failure := func(err error) ItemResult {
		return ItemResult{Error: true, Actual: maintenancePrefix(cs.Option), Message: err.Error()}
	}
	if !validMaintenance(cs) {
		return failure(fmt.Errorf("systemd维护需完整固定参考"))
	}
	var first maintenanceSnapshot
	var lastClock kernelClockSample
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			return failure(fmt.Errorf("systemd维护超过共同截止时间"))
		}
		s, err := collectMaintenance(ctx, cs.Option, targets, q)
		if err != nil {
			return failure(err)
		}
		lastClock = s.Clock
		r := evaluateMaintenance(cs.Option, targets, s)
		if r.Error {
			return r
		}
		if i == 0 {
			first = s
		} else {
			// Kernel error estimates vary naturally; only the selected state/status
			// are stability predicates. The second estimates remain separate evidence.
			a, b := first, s
			a.Clock.MaxError = 0
			a.Clock.EstError = 0
			b.Clock.MaxError = 0
			b.Clock.EstError = 0
			if !reflect.DeepEqual(a, b) {
				return failure(fmt.Errorf("systemd维护单元、命令、调度或内核同步指示在查询期间变化"))
			}
		}
		if ctx.Err() != nil {
			return failure(fmt.Errorf("systemd维护超过共同截止时间"))
		}
	}
	r := evaluateMaintenance(cs.Option, targets, first)
	if cs.Option == "time_sync" {
		r.Actual += fmt.Sprintf(" sample_2_max_error_us=%d sample_2_est_error_us=%d", lastClock.MaxError, lastClock.EstError)
	}
	return r
}
func collectMaintenance(ctx context.Context, option string, t maintenanceTargets, q maintenanceQueries) (maintenanceSnapshot, error) {
	s := maintenanceSnapshot{}
	var err error
	s.Manager, err = maintenanceProperties(q.show("Version,SystemState", ""), []string{"Version", "SystemState"}, nil)
	if err != nil {
		return s, err
	}
	if !ctrlAltDelVersion.MatchString(s.Manager["Version"]) {
		return s, fmt.Errorf("维护参考限定已加载systemd255")
	}
	service := t.sync
	if option == "tmpfiles_clean" {
		service = t.cleaner
		s.Timer, err = maintenanceProperties(q.show(maintenanceBaseProperties+",Unit", t.timer), []string{"Id", "LoadState", "ActiveState", "SubState", "NeedDaemonReload", "Unit"}, []string{"Unit"})
		if err != nil {
			return s, err
		}
	}
	if ctx.Err() != nil {
		return s, fmt.Errorf("systemd维护查询超时")
	}
	s.Service, err = maintenanceProperties(q.show(maintenanceBaseProperties+",Type,RemainAfterExit,MainPID", service), []string{"Id", "LoadState", "ActiveState", "SubState", "NeedDaemonReload", "Type", "RemainAfterExit", "MainPID"}, nil)
	if err != nil {
		return s, err
	}
	if ctx.Err() != nil {
		return s, fmt.Errorf("systemd维护查询超时")
	}
	// Request exactly these properties, never GetAll, Environment or credentials.
	s.Command, err = parseMaintenanceCommand(q.property(service, "Service", "ExecStart"))
	if err != nil {
		return s, err
	}
	if option == "tmpfiles_clean" {
		raw, err := maintenanceBusData(q.property(t.timer, "Timer", "NextElapseUSecMonotonic"), "t")
		if err != nil {
			return s, err
		}
		s.Next, err = maintenanceUint(raw, 64)
		if err != nil {
			return s, err
		}
	} else {
		s.Clock, err = q.clock()
		if err != nil {
			return s, fmt.Errorf("内核同步指示读取失败")
		}
	}
	return s, err
}
func maintenanceBase(v map[string]string, target string, timer bool) error {
	if v["Id"] != target || !maintenanceUnitName.MatchString(target) {
		return fmt.Errorf("维护单元身份不符或别名未支持")
	}
	if v["LoadState"] != "loaded" && v["LoadState"] != "masked" {
		return fmt.Errorf("维护单元缺失、加载失败或未知")
	}
	if v["NeedDaemonReload"] != "no" {
		return fmt.Errorf("维护单元待重载或重载证据未知")
	}
	stable := v["ActiveState"] == "inactive" && v["SubState"] == "dead" || v["ActiveState"] == "failed" && v["SubState"] == "failed"
	if timer {
		stable = stable || v["ActiveState"] == "active" && (v["SubState"] == "waiting" || v["SubState"] == "elapsed")
	} else {
		stable = stable || v["ActiveState"] == "active" && (v["SubState"] == "running" || v["SubState"] == "exited")
	}
	if !stable {
		return fmt.Errorf("维护单元切换中或状态未知")
	}
	return nil
}
func evaluateMaintenance(option string, t maintenanceTargets, s maintenanceSnapshot) ItemResult {
	prefix := maintenancePrefix(option)
	failure := func(err error) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: err.Error()} }
	if !ctrlAltDelVersion.MatchString(s.Manager["Version"]) {
		return failure(fmt.Errorf("维护参考限定systemd255"))
	}
	if state := s.Manager["SystemState"]; state != "running" && state != "degraded" && state != "maintenance" {
		return failure(fmt.Errorf("管理器状态切换中或未知"))
	}
	target := t.sync
	if option == "tmpfiles_clean" {
		target = t.cleaner
	}
	if err := maintenanceBase(s.Service, target, false); err != nil {
		return failure(err)
	}
	pid, err := strconv.ParseUint(s.Service["MainPID"], 10, 32)
	if err != nil || strconv.FormatUint(pid, 10) != s.Service["MainPID"] || s.Service["ActiveState"] == "active" && s.Service["SubState"] == "running" && pid <= 1 {
		return failure(fmt.Errorf("维护MainPID不完整或未知"))
	}
	if s.Service["RemainAfterExit"] != "yes" && s.Service["RemainAfterExit"] != "no" {
		return failure(fmt.Errorf("维护RemainAfterExit未知"))
	}
	switch s.Service["Type"] {
	case "simple", "exec", "forking", "oneshot", "dbus", "notify", "notify-reload", "idle":
	default:
		return failure(fmt.Errorf("维护服务类型未知"))
	}
	command := s.Command.matches(option)
	passed := s.Service["LoadState"] == "loaded" && command
	actual := fmt.Sprintf("%sVersion=%s SystemState=%s service=%s LoadState=%s ActiveState=%s SubState=%s Type=%s MainPID=%d command_reference_match=%t", prefix, s.Manager["Version"], s.Manager["SystemState"], target, s.Service["LoadState"], s.Service["ActiveState"], s.Service["SubState"], s.Service["Type"], pid, command)
	if option == "tmpfiles_clean" {
		if err := maintenanceBase(s.Timer, t.timer, true); err != nil {
			return failure(err)
		}
		if s.Timer["Unit"] != "" && !maintenanceUnitName.MatchString(s.Timer["Unit"]) {
			return failure(fmt.Errorf("清理定时器目标未知"))
		}
		passed = passed && s.Service["Type"] == "oneshot" && s.Service["RemainAfterExit"] == "no" && s.Service["ActiveState"] == "inactive" && s.Service["SubState"] == "dead" && pid == 0 && s.Timer["LoadState"] == "loaded" && s.Timer["ActiveState"] == "active" && s.Timer["SubState"] == "waiting" && s.Timer["Unit"] == t.cleaner && s.Next > 0 && s.Next != ^uint64(0)
		actual += fmt.Sprintf(" timer=%s TimerLoadState=%s TimerActiveState=%s TimerSubState=%s Unit=%s next_monotonic_us=%d RemainAfterExit=%s", t.timer, s.Timer["LoadState"], s.Timer["ActiveState"], s.Timer["SubState"], s.Timer["Unit"], s.Next, s.Service["RemainAfterExit"])
	} else if option == "time_sync" {
		if s.Clock.State < 0 || s.Clock.State > 5 || s.Clock.Status > 0xffff || s.Clock.MaxError < 0 || s.Clock.EstError < 0 {
			return failure(fmt.Errorf("内核同步指示或误差估计值未知"))
		}
		passed = passed && s.Service["Type"] == "notify" && s.Service["ActiveState"] == "active" && s.Service["SubState"] == "running" && s.Clock.State < 5 && s.Clock.Status&(0x40|0x1000) == 0
		actual += fmt.Sprintf(" clock_source=kernel-realtime kernel_state=%d kernel_status=0x%x max_error_us=%d est_error_us=%d", s.Clock.State, s.Clock.Status, s.Clock.MaxError, s.Clock.EstError)
	} else {
		return failure(fmt.Errorf("维护参考项未支持"))
	}
	message := ""
	if !passed {
		message = "已加载维护单元或内核同步指示未满足完整参考；执行和交付边界仍未验证"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
