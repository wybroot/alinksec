package baseline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

const appArmorReference = "enabled=Y,lsm=apparmor,global_mode=enforce,root_unstacked_view,profiles=nonempty/all_enforce"
const appArmorMaxProfiles = 1024
const appArmorMaxBytes = 256 * 1024

func validAppArmor(cs *CheckSpec) bool {
	return cs.Type == "apparmor_runtime" && cs.Target == "current-kernel" && cs.Operator == "eq" && cs.Expected == appArmorReference
}

func appArmorPrefix() string {
	return "scope=current-apparmor-root-view policy_content_state=unverified application_attachment_state=unverified effective_access_state=unverified unloaded_profiles_state=unverified other_security_mechanisms_state=unverified host_policy_coverage_state=unverified persistence_state=unverified snapshot_state=non_atomic "
}

type appArmorSnapshot struct {
	Values, Identities map[string]string
}

func observeAppArmor(ctx context.Context, cs *CheckSpec, read func() (appArmorSnapshot, error)) ItemResult {
	failure := func(message string) ItemResult {
		return ItemResult{Error: true, Actual: appArmorPrefix(), Message: message}
	}
	if !validAppArmor(cs) {
		return failure("AppArmor需固定当前内核及完整模式参考")
	}
	var first appArmorSnapshot
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			return failure("AppArmor观测超过共同截止时间")
		}
		s, err := read()
		if err != nil {
			// Never echo profile names, raw kernel output or injected reader errors.
			return failure("AppArmor内核接口缺失、权限不足、身份或读取状态不可确认")
		}
		if r := evaluateAppArmor(s); r.Error {
			return r
		}
		if i == 0 {
			first = s
		} else if !reflect.DeepEqual(first, s) {
			return failure("AppArmor参数、策略集合、路径或策略视图在观测期间变化")
		}
	}
	if ctx.Err() != nil {
		return failure("AppArmor观测超过共同截止时间")
	}
	return evaluateAppArmor(first)
}

var appArmorLSMName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func appArmorLSM(raw string) (bool, error) {
	// securityfs lsm_read returns exactly strlen(lsm_names), with no newline.
	// The bounded reader must reach EOF; line-oriented parameter rules do not apply.
	if len(raw) == 0 || len(raw) > 1024 {
		return false, fmt.Errorf("LSM列表格式未支持")
	}
	names := strings.Split(raw, ",")
	if len(names) > 32 {
		return false, fmt.Errorf("LSM数量超限")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !appArmorLSMName.MatchString(name) || seen[name] {
			return false, fmt.Errorf("LSM名称或重复列表未支持")
		}
		seen[name] = true
	}
	return seen["apparmor"], nil
}

func appArmorMode(value string) bool {
	return value == "enforce" || value == "complain" || value == "kill" || value == "unconfined"
}

func parseAppArmorProfiles(raw string) (map[string]string, error) {
	profiles := map[string]string{}
	if len(raw) > appArmorMaxBytes || raw != "" && !strings.HasSuffix(raw, "\n") {
		return nil, fmt.Errorf("AppArmor策略列表超限或不完整")
	}
	if raw == "" {
		return profiles, nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		at := strings.LastIndex(line, " (")
		if len(line) > 1024 || at < 1 || !strings.HasSuffix(line, ")") || len(profiles) >= appArmorMaxProfiles {
			return nil, fmt.Errorf("AppArmor策略行、数量或类型未支持")
		}
		name, mode := line[:at], line[at+2:len(line)-1]
		// Names in this finite root view may include spaces and child hats, but
		// not namespace/stack delimiters, parentheses, escapes or control bytes.
		if strings.TrimSpace(name) != name || strings.ContainsAny(name, ":&()\\") || profiles[name] != "" || !appArmorMode(mode) {
			return nil, fmt.Errorf("AppArmor策略名称、命名空间、重复或模式未支持")
		}
		for _, c := range []byte(name) {
			if c < 32 || c > 126 {
				return nil, fmt.Errorf("AppArmor策略名称字节未支持")
			}
		}
		profiles[name] = mode
	}
	return profiles, nil
}

func evaluateAppArmor(s appArmorSnapshot) ItemResult {
	failure := func(message string) ItemResult {
		return ItemResult{Error: true, Actual: appArmorPrefix(), Message: message}
	}
	v := s.Values
	if v["enabled"] != "Y\n" && v["enabled"] != "N\n" {
		return failure("AppArmor启用值未知或不完整")
	}
	present, err := appArmorLSM(v["lsm"])
	if err != nil || v["enabled"] == "N\n" && present {
		return failure("AppArmor与LSM状态未知、不完整或不一致")
	}
	if v["enabled"] == "N\n" || !present {
		if len(v) != 2 {
			return failure("AppArmor未启用状态含无法解释的额外观测")
		}
		return ItemResult{Actual: fmt.Sprintf("%senabled=%s lsm_apparmor=%t global_mode=not_observed profiles=not_observed", appArmorPrefix(), strings.TrimSuffix(v["enabled"], "\n"), present), Message: "当前内核AppArmor未满足启用参考"}
	}
	if len(v) != 7 || v["level"] != "0\n" || v["stacked"] != "no\n" || v["ns_stacked"] != "no\n" {
		return failure("AppArmor需完整根策略视图；嵌套或叠加视图尚未支持")
	}
	if _, ok := v["profiles"]; !ok {
		return failure("AppArmor策略列表观测缺失")
	}
	mode := strings.TrimSuffix(v["mode"], "\n")
	if !appArmorMode(mode) {
		return failure("AppArmor全局模式未知或不完整")
	}
	profiles, err := parseAppArmorProfiles(v["profiles"])
	if err != nil {
		return failure("AppArmor策略列表未知、重复、超限或不完整")
	}
	counts := map[string]int{}
	for _, mode := range profiles {
		counts[mode]++
	}
	passed := mode == "enforce" && len(profiles) > 0 && counts["enforce"] == len(profiles)
	actual := fmt.Sprintf("%senabled=Y lsm_apparmor=true view_level=0 stacked=no ns_stacked=no global_mode=%s profiles=%d enforce=%d complain=%d kill=%d unconfined=%d inventory_sha256=%x", appArmorPrefix(), mode, len(profiles), counts["enforce"], counts["complain"], counts["kill"], counts["unconfined"], sha256.Sum256([]byte(v["profiles"])))
	message := ""
	if !passed {
		message = "当前AppArmor全局或全部已加载策略模式未满足非空/全部enforce参考"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
