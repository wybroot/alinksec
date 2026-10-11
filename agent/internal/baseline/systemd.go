package baseline

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Query the local system manager with fixed arguments, never a shell or a
// candidate-supplied executable. Unit status is an observation, not proof that
// audit events are captured or logs are delivered. No start/stop/reload calls.
func checkSystemdService(cs *CheckSpec) ItemResult {
	if runtime.GOOS != "linux" {
		return ItemResult{Error: true, Message: "systemd_service 当前仅支持 Linux systemd"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "show", "--all",
		"--property=Id,LoadState,ActiveState,SubState,MainPID", "--", cs.Target)
	// Do not inherit D-Bus addresses or SYSTEMD_* switches that redirect queries
	// to another manager, change output or enable remote transports.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	return evaluateSystemdService(collectBaselineCommand(ctx, cmd, cs.TimeoutMs), cs.Target)
}

func evaluateSystemdService(query ItemResult, unit string) ItemResult {
	prefix := "manager=local-system unit=" + unit + " "
	if query.Error {
		query.Actual = prefix + query.Actual
		return query
	}
	values := map[string]string{}
	for _, line := range strings.Split(query.Actual, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "Id" && key != "LoadState" && key != "ActiveState" && key != "SubState" && key != "MainPID") {
			return ItemResult{Error: true, Actual: prefix, Message: "systemd 查询含未知或无效属性"}
		}
		if _, exists := values[key]; exists || value == "" || strings.TrimSpace(value) != value {
			return ItemResult{Error: true, Actual: prefix, Message: "systemd 查询属性重复、为空或格式无效"}
		}
		values[key] = value
	}
	actual := fmt.Sprintf("%sId=%s LoadState=%s ActiveState=%s SubState=%s MainPID=%s", prefix,
		values["Id"], values["LoadState"], values["ActiveState"], values["SubState"], values["MainPID"])
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: actual, Message: message} }
	if len(values) != 5 || values["Id"] != unit {
		return failure("systemd 查询属性不完整或解析到其他单元；别名不在此检查范围")
	}
	pid, err := strconv.ParseUint(values["MainPID"], 10, 32)
	if err != nil || strconv.FormatUint(pid, 10) != values["MainPID"] {
		return failure("systemd MainPID 不是有效的规范非负整数")
	}
	load, active, sub := values["LoadState"], values["ActiveState"], values["SubState"]
	if load != "loaded" && load != "masked" {
		return failure("systemd 单元缺失、加载异常或加载状态尚未支持")
	}
	// Conservative stable snapshots. Transitional/unknown states must be retried
	// by the administrator, rather than published as completed noncompliance.
	stable := active == "active" && (sub == "running" || sub == "exited") ||
		active == "inactive" && sub == "dead" || active == "failed" && sub == "failed"
	if !stable || active == "active" && sub == "running" && pid <= 1 {
		return failure("systemd 状态正在切换、尚未支持或运行主进程证据不完整")
	}
	passed := load == "loaded" && active == "active" && sub == "running"
	message := ""
	if !passed {
		message = "服务未满足 loaded/active/running 参考；未确认持续审计或日志交付"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
