package baseline

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"log/slog"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// ItemResult 单项核查结论
type ItemResult struct {
	ItemID     string
	Passed     bool
	Actual     string // 实际检测值（取证）
	Message    string // 失败原因（人读）
	DurationMs uint32
	Error      bool
}

const MaxChecks = 500
const maxFileBytes = 8 * 1024 * 1024
const maxCommandBytes = 64 * 1024

func evidence(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value
	}
	end := limit
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + "…"
}

// Run 执行全部检查项（串行执行：避免命令型检查并发放大主机负载）
func Run(taskID string, specs []*pb.BaselineCheckSpec, log *slog.Logger) *pb.RptBaselineResult {
	result := &pb.RptBaselineResult{TaskId: taskID}
	if len(specs) > MaxChecks {
		log.Warn("基线检查项超过上限，拒绝执行", "items", len(specs))
		return result
	}
	deadline := time.Now().Add(20 * time.Minute)
	for _, spec := range specs {
		start := time.Now()
		r := ItemResult{ItemID: spec.GetItemId(), Error: true, Message: "基线任务超过 20 分钟执行预算"}
		if time.Now().Before(deadline) {
			r = checkOne(spec)
		}
		r.DurationMs = uint32(time.Since(start).Milliseconds())
		r.Actual, r.Message = evidence(r.Actual, 2048), evidence(r.Message, 1024)
		if !r.Passed {
			log.Info("基线项未通过", "item", spec.GetItemId(), "msg", r.Message)
		}
		status := "fail"
		if r.Error {
			status = "error"
		} else if r.Passed {
			status = "pass"
		}
		result.Items = append(result.Items, &pb.BaselineItemResult{
			ItemId:          r.ItemID,
			Passed:          r.Passed,
			Actual:          evidence(r.Actual, 2048),
			Message:         evidence(r.Message, 1024),
			DurationMs:      r.DurationMs,
			ExecutionStatus: status,
		})
	}
	return result
}

// checkOne 单项检查入口：解析失败按“检查异常”落库（passed=false，不中断整体）
func checkOne(spec *pb.BaselineCheckSpec) ItemResult {
	cs, err := ParseCheck(spec.GetCheck())
	if err != nil {
		return ItemResult{ItemID: spec.GetItemId(), Error: true, Actual: spec.GetCheck(), Message: err.Error()}
	}
	var result ItemResult
	switch cs.Type {
	case "file_content":
		result = checkFileContent(cs)
	case "file_line":
		result = checkFileLine(cs)
	case "file_perm":
		result = checkFilePerm(cs)
	case "cmd_output":
		result = checkCmdOutput(cs)
	case "sshd_effective":
		result = checkSSHEffective(cs)
	case "sshd_notice":
		result = checkSSHNotice(cs)
	case "shadow_account_defaults":
		result = checkShadowAccountDefaults(cs)
	case "local_identity_file", "local_accounts":
		result = checkLocalIdentity(cs)
	case "pam_password":
		result = checkPAMPassword(cs)
	case "pam_auth":
		result = checkPAMAuth(cs)
	case "pam_limits":
		result = checkPAMLimits(cs)
	case "systemd_service":
		result = checkSystemdService(cs)
	case "systemd_ctrl_alt_del":
		result = checkCtrlAltDel(cs)
	case "linux_log_metadata":
		result = checkLogMetadata(cs)
	case "linux_audit":
		result = checkLinuxAudit(cs)
	case "auditd_config":
		result = checkAuditdConfig(cs)
	case "debian_cron_metadata":
		result = checkCronMetadata(cs)
	case "sudoers_policy":
		result = checkSudoers(cs)
	case "apt_install_policy":
		result = checkAPTPolicy(cs)
	case "apt_sources_policy":
		result = checkAPTSources(cs)
	case "rsyslog_cron_routing":
		result = checkRsyslogCron(cs)
	default:
		result = ItemResult{Error: true, Message: "未知检查类型 " + cs.Type}
	}
	result.ItemID = spec.GetItemId()
	return result
}

// Verify 复核入口（fixer 修复后重跑检查用）：checkJSON 是否通过。
func Verify(checkJSON string) (bool, string) {
	r := checkOne(&pb.BaselineCheckSpec{ItemId: "verify", Check: checkJSON})
	return r.Passed, r.Message
}

/* ==================== file_content ==================== */

// checkFileContent 目标文件任意一行匹配 regex 即通过
func checkFileContent(cs *CheckSpec) ItemResult {
	lines, err := readLinesWithin(cs.Target, time.Now().Add(time.Duration(cs.TimeoutMs)*time.Millisecond))
	if err != nil {
		return ItemResult{Error: !os.IsNotExist(err), Actual: cs.Target, Message: "读取文件失败: " + err.Error()}
	}
	re, err := regexp.Compile(cs.Regex)
	if err != nil {
		return ItemResult{Error: true, Message: "regex 编译失败: " + err.Error()}
	}
	for _, l := range lines {
		if re.MatchString(l) {
			return ItemResult{Passed: true, Actual: strings.TrimSpace(l)}
		}
	}
	return ItemResult{Passed: false, Actual: "", Message: fmt.Sprintf("文件 %s 中未找到匹配 %s 的配置行", cs.Target, cs.Regex)}
}

/* ==================== file_line ==================== */

// checkFileLine 行级断言：regex / contains / not_contains
func checkFileLine(cs *CheckSpec) ItemResult {
	lines, err := readLinesWithin(cs.Target, time.Now().Add(time.Duration(cs.TimeoutMs)*time.Millisecond))
	if err != nil {
		return ItemResult{Error: !os.IsNotExist(err), Actual: cs.Target, Message: "读取文件失败: " + err.Error()}
	}
	var re *regexp.Regexp
	if cs.Operator == "regex" {
		if re, err = regexp.Compile(cs.Expected); err != nil {
			return ItemResult{Error: true, Message: "regex 编译失败: " + err.Error()}
		}
	}
	for _, l := range lines {
		var hit bool
		switch cs.Operator {
		case "regex":
			hit = re != nil && re.MatchString(l)
		case "contains":
			hit = strings.Contains(l, cs.Expected)
		case "not_contains":
			// 命中敏感内容即失败，提前返回取证行
			if strings.Contains(l, cs.Expected) {
				return ItemResult{Passed: false, Actual: strings.TrimSpace(l),
					Message: fmt.Sprintf("文件 %s 含禁止内容 %q", cs.Target, cs.Expected)}
			}
			continue
		default:
			return ItemResult{Error: true, Message: "不支持的 operator: " + cs.Operator}
		}
		if hit {
			return ItemResult{Passed: true, Actual: strings.TrimSpace(l)}
		}
	}
	if cs.Operator == "not_contains" {
		return ItemResult{Passed: true, Actual: "未包含禁止内容"}
	}
	return ItemResult{Passed: false, Actual: "",
		Message: fmt.Sprintf("文件 %s 中未找到满足 %s %q 的行", cs.Target, cs.Operator, cs.Expected)}
}

/* ==================== file_perm ==================== */
// checkFilePerm 按平台实现：perm_linux.go（stat 元数据）/ perm_windows.go（不支持）

/* ==================== cmd_output ==================== */

// checkCmdOutput executes only an Agent-compiled baseline command and then
// evaluates its output. The server-provided command is a selector, never an
// unrestricted remote command channel.
func checkCmdOutput(cs *CheckSpec) ItemResult {
	if !isApprovedCmdOutput(cs.Cmd) {
		return ItemResult{Error: true, Message: "基线命令未获 Agent 白名单许可"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// The exact approved selector contains a fixed PowerShell script. Pass
		// it as one argument: cmd.exe would add a second layer of quoting and
		// turn the script into a string literal instead of executing the query.
		const prefix = "powershell.exe -NoProfile -NonInteractive -Command \""
		script, ok := strings.CutPrefix(cs.Cmd, prefix)
		if !ok || !strings.HasSuffix(script, "\"") {
			return ItemResult{Error: true, Message: "不支持的 Windows 基线命令格式"}
		}
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", strings.TrimSuffix(script, "\""))
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cs.Cmd)
	}
	return executeBaselineCommand(ctx, cmd, cs)
}

// Bound both output and waits for inherited pipes; Linux kills the process group.
func executeBaselineCommand(ctx context.Context, cmd *exec.Cmd, cs *CheckSpec) ItemResult {
	result := collectBaselineCommand(ctx, cmd, cs.TimeoutMs)
	if result.Error {
		return result
	}
	return evaluateOutput(result.Actual, cs)
}

func collectBaselineCommand(ctx context.Context, cmd *exec.Cmd, timeoutMs int) ItemResult {
	configureBaselineCommand(cmd)
	defer cleanupBaselineCommand(cmd)
	cmd.WaitDelay = 250 * time.Millisecond
	outputBuffer := &boundedOutput{}
	outputBuffer.stop = func() {
		if cmd.Cancel != nil {
			_ = cmd.Cancel()
		} else if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	cmd.Stdout, cmd.Stderr = outputBuffer, outputBuffer
	err := cmd.Run()
	output := strings.TrimSpace(outputBuffer.buffer.String())
	if outputBuffer.exceeded {
		return ItemResult{Error: true, Actual: evidence(output, 2048), Message: "命令输出超过 64 KiB 上限"}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return ItemResult{Error: true, Actual: output,
			Message: fmt.Sprintf("命令执行超时（%dms）", timeoutMs)}
	}
	if err != nil {
		return ItemResult{Error: true, Actual: output, Message: "命令执行失败: " + err.Error()}
	}
	return ItemResult{Actual: output}
}

type boundedOutput struct {
	mutex    sync.Mutex
	buffer   bytes.Buffer
	exceeded bool
	stop     func()
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	remaining := maxCommandBytes - b.buffer.Len()
	if len(p) > remaining {
		if !b.exceeded && b.stop != nil {
			b.stop()
		}
		b.exceeded = true
		b.buffer.Write(p[:remaining])
	} else {
		b.buffer.Write(p)
	}
	return len(p), nil
}

func evaluateOutput(output string, cs *CheckSpec) ItemResult {
	var re *regexp.Regexp
	if cs.Operator == "regex" {
		var rerr error
		if re, rerr = regexp.Compile(cs.Expected); rerr != nil {
			return ItemResult{Error: true, Message: "regex 编译失败: " + rerr.Error()}
		}
	}
	switch cs.Operator {
	case "eq", "":
		if output == cs.Expected {
			return ItemResult{Passed: true, Actual: output}
		}
	case "ne":
		if output != cs.Expected {
			return ItemResult{Passed: true, Actual: output}
		}
	case "contains":
		if strings.Contains(output, cs.Expected) {
			return ItemResult{Passed: true, Actual: output}
		}
	case "not_contains":
		if !strings.Contains(output, cs.Expected) {
			return ItemResult{Passed: true, Actual: output}
		}
	case "regex":
		if re != nil && re.MatchString(output) {
			return ItemResult{Passed: true, Actual: output}
		}
	case "gt", "gte", "lt", "lte":
		actual, actualErr := strconv.ParseFloat(output, 64)
		expected, expectedErr := strconv.ParseFloat(cs.Expected, 64)
		if actualErr != nil || expectedErr != nil || math.IsNaN(actual) || math.IsNaN(expected) || math.IsInf(actual, 0) || math.IsInf(expected, 0) {
			return ItemResult{Error: true, Actual: output, Message: "数值比较需要有限数值输出与期望值"}
		}
		passed := cs.Operator == "gt" && actual > expected || cs.Operator == "gte" && actual >= expected ||
			cs.Operator == "lt" && actual < expected || cs.Operator == "lte" && actual <= expected
		if passed {
			return ItemResult{Passed: true, Actual: output}
		}
	default:
		return ItemResult{Error: true, Actual: output, Message: "不支持的 operator: " + cs.Operator}
	}
	return ItemResult{Passed: false, Actual: output,
		Message: fmt.Sprintf("输出 %q 不满足 %s %q", output, cs.Operator, cs.Expected)}
}

/* ==================== 工具 ==================== */

// Only regular files are read, with bounded bytes, lines and elapsed scanning time.
func readLines(path string) ([]string, error) {
	return readLinesWithin(path, time.Now().Add(5*time.Second))
}
func readLinesWithin(path string, deadline time.Time) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return nil, fmt.Errorf("检查文件必须为不超过 8 MiB 的普通文件")
	}
	f, err := openBaselineFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("检查目标不是普通文件")
	}
	var lines []string
	reader := &io.LimitedReader{R: f, N: maxFileBytes + 1}
	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(lines) >= 16384 {
			return nil, fmt.Errorf("检查文件超过 16384 行上限")
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("文件检查超时")
		}
		lines = append(lines, sc.Text())
	}
	if reader.N == 0 {
		return nil, fmt.Errorf("检查文件超过 8 MiB 上限")
	}
	if time.Now().After(deadline) {
		return nil, fmt.Errorf("文件检查超时")
	}
	return lines, sc.Err()
}
