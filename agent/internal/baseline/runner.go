package baseline

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

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
}

// Run 执行全部检查项（串行执行：避免命令型检查并发放大主机负载）
func Run(taskID string, specs []*pb.BaselineCheckSpec, log *slog.Logger) *pb.RptBaselineResult {
	result := &pb.RptBaselineResult{TaskId: taskID}
	for _, spec := range specs {
		start := time.Now()
		r := checkOne(spec)
		r.DurationMs = uint32(time.Since(start).Milliseconds())
		if !r.Passed {
			log.Info("基线项未通过", "item", spec.GetItemId(), "msg", r.Message)
		}
		result.Items = append(result.Items, &pb.BaselineItemResult{
			ItemId:     r.ItemID,
			Passed:     r.Passed,
			Actual:     r.Actual,
			Message:    r.Message,
			DurationMs: r.DurationMs,
		})
	}
	return result
}

// checkOne 单项检查入口：解析失败按“检查异常”落库（passed=false，不中断整体）
func checkOne(spec *pb.BaselineCheckSpec) ItemResult {
	cs, err := ParseCheck(spec.GetCheck())
	if err != nil {
		return ItemResult{ItemID: spec.GetItemId(), Passed: false, Actual: spec.GetCheck(), Message: err.Error()}
	}
	switch cs.Type {
	case "file_content":
		return checkFileContent(cs)
	case "file_line":
		return checkFileLine(cs)
	case "file_perm":
		return checkFilePerm(cs)
	case "cmd_output":
		return checkCmdOutput(cs)
	}
	return ItemResult{ItemID: spec.GetItemId(), Passed: false, Message: "未知检查类型 " + cs.Type}
}

// Verify 复核入口（fixer 修复后重跑检查用）：checkJSON 是否通过。
func Verify(checkJSON string) (bool, string) {
	r := checkOne(&pb.BaselineCheckSpec{ItemId: "verify", Check: checkJSON})
	return r.Passed, r.Message
}

/* ==================== file_content ==================== */

// checkFileContent 目标文件任意一行匹配 regex 即通过
func checkFileContent(cs *CheckSpec) ItemResult {
	lines, err := readLines(cs.Target)
	if err != nil {
		return ItemResult{Passed: false, Actual: cs.Target, Message: "读取文件失败: " + err.Error()}
	}
	re, err := regexp.Compile(cs.Regex)
	if err != nil {
		return ItemResult{Passed: false, Message: "regex 编译失败: " + err.Error()}
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
	lines, err := readLines(cs.Target)
	if err != nil {
		return ItemResult{Passed: false, Actual: cs.Target, Message: "读取文件失败: " + err.Error()}
	}
	var re *regexp.Regexp
	if cs.Operator == "regex" {
		if re, err = regexp.Compile(cs.Expected); err != nil {
			return ItemResult{Passed: false, Message: "regex 编译失败: " + err.Error()}
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
			return ItemResult{Passed: false, Message: "不支持的 operator: " + cs.Operator}
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
		return ItemResult{Passed: false, Message: "基线命令未获 Agent 白名单许可"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", cs.Cmd)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cs.Cmd)
	}
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return ItemResult{Passed: false, Actual: output,
			Message: fmt.Sprintf("命令执行超时（%dms）", cs.TimeoutMs)}
	}
	if err != nil {
		return ItemResult{Passed: false, Actual: output, Message: "命令执行失败: " + err.Error()}
	}

	var re *regexp.Regexp
	if cs.Operator == "regex" {
		var rerr error
		if re, rerr = regexp.Compile(cs.Expected); rerr != nil {
			return ItemResult{Passed: false, Message: "regex 编译失败: " + rerr.Error()}
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
	default:
		return ItemResult{Passed: false, Actual: output, Message: "不支持的 operator: " + cs.Operator}
	}
	return ItemResult{Passed: false, Actual: output,
		Message: fmt.Sprintf("输出 %q 不满足 %s %q", output, cs.Operator, cs.Expected)}
}

/* ==================== 工具 ==================== */

// readLines 逐行读取文件（大文件安全：bufio 流式）
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}
