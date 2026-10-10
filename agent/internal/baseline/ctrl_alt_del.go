package baseline

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const ctrlAltDelReference = "masked/inactive/dead,burst_action=none"

var ctrlAltDelVersion = regexp.MustCompile(`^255(\.[0-9]+)?(-[A-Za-z0-9.+~]+)?$`)
var ctrlAltDelTargetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]*\.target$`)

func checkCtrlAltDel(cs *CheckSpec) ItemResult {
	if runtime.GOOS != "linux" {
		return ItemResult{Error: true, Message: "systemd_ctrl_alt_del 当前仅支持 Linux systemd 255"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	return observeCtrlAltDel(ctx, cs.TimeoutMs, cs.Target, func(properties, target string) ItemResult {
		args := []string{"--system", "--no-pager", "show", "--all", "--property=" + properties}
		if target != "" {
			args = append(args, "--", target)
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
		return collectBaselineCommand(ctx, cmd, cs.TimeoutMs)
	})
}

// Two observations share one deadline. They detect observed changes, but are
// neither an atomic manager transaction nor proof of persistence after reboot.
func observeCtrlAltDel(ctx context.Context, timeout int, target string, query func(string, string) ItemResult) ItemResult {
	var first ItemResult
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			return ItemResult{Error: true, Actual: first.Actual, Message: "Ctrl-Alt-Del 查询超过共同截止时间"}
		}
		manager := query("Version,SystemState,CtrlAltDelBurstAction", "")
		if manager.Error {
			return evaluateCtrlAltDel(manager, ItemResult{}, target)
		}
		if ctx.Err() != nil {
			return ItemResult{Error: true, Actual: first.Actual, Message: "Ctrl-Alt-Del 查询超过共同截止时间"}
		}
		unit := query("Id,Names,LoadState,ActiveState,SubState,UnitFileState,NeedDaemonReload", target)
		result := evaluateCtrlAltDel(manager, unit, target)
		if result.Error {
			return result
		}
		if ctx.Err() != nil {
			return ItemResult{Error: true, Actual: result.Actual, Message: "Ctrl-Alt-Del 查询超过共同截止时间"}
		}
		if i == 0 {
			first = result
		} else if result.Actual != first.Actual || result.Passed != first.Passed {
			return ItemResult{Error: true, Actual: result.Actual, Message: "Ctrl-Alt-Del 管理器或目标状态在查询期间变化"}
		}
	}
	return first
}

func ctrlAltDelProperties(query ItemResult, keys []string, allowEmpty string) (map[string]string, error) {
	values := make(map[string]string, len(keys))
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for _, line := range strings.Split(query.Actual, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] || strings.TrimSpace(value) != value || value == "" && key != allowEmpty || strings.ContainsAny(value, "\r\x00") {
			return nil, fmt.Errorf("Ctrl-Alt-Del 查询含未知、为空或无效属性")
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("Ctrl-Alt-Del 查询属性重复")
		}
		values[key] = value
	}
	if len(values) != len(keys) {
		return nil, fmt.Errorf("Ctrl-Alt-Del 查询属性不完整")
	}
	return values, nil
}

func evaluateCtrlAltDel(manager, unit ItemResult, target string) ItemResult {
	prefix := "scope=loaded-systemd-ctrl-alt-del manager=local-system unit=" + target + " persistence_state=unverified keyboard_path_state=unverified trigger_test_state=unverified "
	for _, query := range []ItemResult{manager, unit} {
		if query.Error {
			query.Actual = prefix + query.Actual
			return query
		}
	}
	m, err := ctrlAltDelProperties(manager, []string{"Version", "SystemState", "CtrlAltDelBurstAction"}, "")
	if err != nil {
		return ItemResult{Error: true, Actual: prefix, Message: err.Error()}
	}
	u, err := ctrlAltDelProperties(unit, []string{"Id", "Names", "LoadState", "ActiveState", "SubState", "UnitFileState", "NeedDaemonReload"}, "UnitFileState")
	if err != nil {
		return ItemResult{Error: true, Actual: prefix, Message: err.Error()}
	}
	names := strings.Fields(u["Names"])
	sort.Strings(names)
	actual := fmt.Sprintf("%sVersion=%s SystemState=%s CtrlAltDelBurstAction=%s Id=%s Names=%s LoadState=%s ActiveState=%s SubState=%s UnitFileState=%s NeedDaemonReload=%s",
		prefix, m["Version"], m["SystemState"], m["CtrlAltDelBurstAction"], u["Id"], strings.Join(names, ","), u["LoadState"], u["ActiveState"], u["SubState"], u["UnitFileState"], u["NeedDaemonReload"])
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: actual, Message: message} }
	if !ctrlAltDelVersion.MatchString(m["Version"]) {
		return failure("Ctrl-Alt-Del 核查限定已加载的 systemd 255 管理器")
	}
	switch m["SystemState"] {
	case "running", "degraded", "maintenance":
	default:
		return failure("systemd 管理器处于切换或未支持状态")
	}
	switch m["CtrlAltDelBurstAction"] {
	case "none", "reboot-force", "reboot-immediate", "poweroff-force", "poweroff-immediate":
	default:
		return failure("CtrlAltDelBurstAction 状态尚未支持")
	}
	if len(u["Id"]) > 256 || !ctrlAltDelTargetName.MatchString(u["Id"]) || len(names) > 32 {
		return failure("systemd 目标身份不在有限支持范围")
	}
	foundTarget, foundID := false, false
	for i, name := range names {
		if len(name) > 256 || !ctrlAltDelTargetName.MatchString(name) || i > 0 && name == names[i-1] {
			return failure("systemd 目标名称集合无效")
		}
		foundTarget = foundTarget || name == target
		foundID = foundID || name == u["Id"]
	}
	if !foundTarget || !foundID {
		return failure("systemd 查询未确认指定目标及其规范身份")
	}
	if u["NeedDaemonReload"] != "no" {
		return failure("systemd 目标需重新加载或加载证据无法确认")
	}
	if u["LoadState"] != "loaded" && u["LoadState"] != "masked" {
		return failure("systemd 目标缺失、加载异常或状态尚未支持")
	}
	switch u["UnitFileState"] {
	case "enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "static", "disabled", "indirect", "generated", "transient", "masked", "masked-runtime":
	default:
		return failure("systemd 目标文件状态尚未支持")
	}
	stable := u["ActiveState"] == "inactive" && u["SubState"] == "dead" || u["ActiveState"] == "active" && u["SubState"] == "active"
	if !stable {
		return failure("systemd 目标处于切换或未支持状态")
	}
	passed := u["Id"] == target && u["LoadState"] == "masked" && u["ActiveState"] == "inactive" &&
		(u["UnitFileState"] == "masked" || u["UnitFileState"] == "masked-runtime") && m["CtrlAltDelBurstAction"] == "none"
	message := ""
	if !passed {
		message = "已加载目标或连续按键动作未满足 masked/inactive/dead 与 burst_action=none 参考"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
