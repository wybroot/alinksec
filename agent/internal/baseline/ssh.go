package baseline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Evaluate the on-disk configuration with OpenSSH itself, including Include,
// first-value semantics and Match. This does not inspect a running daemon or
// connect to the supplied addresses. The executable and arguments are fixed.
func checkSSHEffective(cs *CheckSpec) ItemResult {
	if runtime.GOOS != "linux" {
		return ItemResult{Error: true, Message: "sshd_effective 当前仅支持 Linux OpenSSH"}
	}
	if err := cs.Connection.validate(); err != nil {
		return ItemResult{Error: true, Message: err.Error()}
	}
	prefix := fmt.Sprintf("config=%s connection=(%s) ", cs.Target, cs.Connection.argument())
	info, err := os.Stat(cs.Target)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return ItemResult{Error: true, Actual: prefix, Message: "SSH 主配置必须为可读取的普通文件，且不超过 8 MiB"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/sshd", "-T", "-f", cs.Target, "-C", cs.Connection.argument())
	result := collectBaselineCommand(ctx, cmd, cs.TimeoutMs)
	if result.Error {
		result.Actual = prefix + result.Actual
		return result
	}
	value, err := sshOption(result.Actual, cs.Option)
	if err != nil {
		return ItemResult{Error: true, Actual: prefix, Message: err.Error()}
	}
	result = evaluateOutput(value, cs)
	result.Actual = prefix + cs.Option + "=" + value
	return result
}

func sshOption(output, option string) (string, error) {
	if option != "permitrootlogin" && option != "maxauthtries" {
		return "", fmt.Errorf("未支持的 SSH 配置项")
	}
	value, found := "", false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], option) {
			continue
		}
		if found || len(fields) != 2 {
			return "", fmt.Errorf("SSH 解析结果存在重复或无效配置项")
		}
		value, found = fields[1], true
	}
	if !found {
		return "", fmt.Errorf("SSH 解析结果缺少配置项 %s", option)
	}
	if option == "maxauthtries" {
		if _, err := strconv.ParseUint(value, 10, 32); err != nil {
			return "", fmt.Errorf("SSH 认证重试次数不是有效非负整数")
		}
	} else {
		switch value {
		case "yes", "no", "prohibit-password", "without-password", "forced-commands-only":
		default:
			return "", fmt.Errorf("SSH root 登录策略值无效")
		}
	}
	return value, nil
}
