package fixer

import (
	"encoding/json"
	"fmt"
	"strings"

	"log/slog"

	"github.com/alinksec/alinksec-agent/internal/baseline"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// FixSpec 服务端下发的 payload JSON（t_baseline_item.fix_spec + check 合并）
type FixSpec struct {
	Risk            string `json:"risk"`             // auto / manual
	RequiresRestart string `json:"requires_restart"` // 需重启的服务名（仅标记，默认不执行）
	Steps           []Step `json:"steps"`
	Check           string `json:"check"` // 复核用 check JSON（重跑基线检查）
}

// Run 执行修复任务：逐项 备份 → 执行 → 复核 → 失败回滚。
// 单项失败不影响其余项；结果经 RptFixResult 上报。
func Run(taskID string, fixes []*pb.FixItem, workDir string, log *slog.Logger) *pb.RptFixResult {
	result := &pb.RptFixResult{TaskId: taskID}
	for _, f := range fixes {
		result.Results = append(result.GetResults(), fixOne(f, workDir, log))
	}
	return result
}

// fixOne 单项修复事务：备份 → 执行 → 复核 →（失败）回滚
func fixOne(f *pb.FixItem, workDir string, log *slog.Logger) *pb.FixResultItem {
	// 软件包类走独立链路（不回滚，docs/05 §3.3）
	if f.GetType() == pb.FixItem_PACKAGE {
		return fixPackage(f, workDir, log)
	}
	item := &pb.FixResultItem{RefId: f.GetRefId()}
	var logLines []string
	addLog := func(format string, args ...any) {
		logLines = append(logLines, fmt.Sprintf(format, args...))
	}

	spec, err := parseSpec(f.GetPayload())
	if err != nil {
		item.Success, item.Log = false, err.Error()
		return item
	}
	if len(spec.Steps) == 0 {
		item.Success, item.Log = false, "fix_spec 无 steps"
		return item
	}
	if spec.Risk == "manual" {
		item.Success, item.Log = false, "risk=manual 项不支持自动修复（需人工处理）"
		return item
	}

	// 1. 收集并备份全部涉及文件（任一备份失败则放弃该项修复——不留无法回滚的现场）
	var files []string
	for _, s := range spec.Steps {
		files = append(files, stepFiles(s)...)
	}
	backups, err := backupFiles(files)
	if err != nil {
		item.Success, item.Log = false, "备份失败，放弃修复: "+err.Error()
		return item
	}
	addLog("已备份 %d 个目标文件", len(backups))

	// 2. 按序执行 steps（失败即回滚）
	for i, s := range spec.Steps {
		if err := execStep(s, func(msg string, args ...any) { addLog(msg, args...) }); err != nil {
			addLog("步骤 %d（%s）失败: %v，执行回滚", i+1, s.Action, err)
			if rbErr := rollback(backups); rbErr != nil {
				addLog("回滚异常: %v（需人工检查）", rbErr)
				item.Success, item.RolledBack, item.Log = false, false, strings.Join(logLines, "\n")
				return item
			}
			addLog("回滚完成，系统恢复修复前状态")
			item.Success, item.RolledBack, item.Log = false, true, strings.Join(logLines, "\n")
			log.Warn("配置修复失败已回滚", "ref", f.GetRefId(), "step", s.Action, "err", err)
			return item
		}
		addLog("步骤 %d（%s）完成", i+1, s.Action)
	}

	// 3. 复核：重跑 check（通过才认成功；不通过按失败回滚）
	if spec.Check != "" {
		passed, msg := baseline.Verify(spec.Check)
		if !passed {
			addLog("复核未通过: %s，执行回滚", msg)
			if rbErr := rollback(backups); rbErr != nil {
				addLog("回滚异常: %v（需人工检查）", rbErr)
				item.Success, item.Log = false, strings.Join(logLines, "\n")
				return item
			}
			addLog("回滚完成")
			item.Success, item.RolledBack, item.Verified, item.Log =
				false, true, false, strings.Join(logLines, "\n")
			log.Warn("配置修复复核未通过已回滚", "ref", f.GetRefId(), "msg", msg)
			return item
		}
		item.Verified = true
		addLog("复核通过")
	}

	// 4. 需重启服务标记（默认不自动重启，平台展示待重启清单）
	if spec.RequiresRestart != "" {
		item.RebootRequired = true
		addLog("需重启服务 %s 生效（未自动重启，请人工在窗口内处理）", spec.RequiresRestart)
	}

	item.Success, item.Log = true, strings.Join(logLines, "\n")
	log.Info("配置修复完成", "ref", f.GetRefId(), "steps", len(spec.Steps), "verified", item.GetVerified())
	return item
}

func parseSpec(payload string) (*FixSpec, error) {
	if payload == "" {
		return nil, fmt.Errorf("payload 为空")
	}
	var s FixSpec
	if err := json.Unmarshal([]byte(payload), &s); err != nil {
		return nil, fmt.Errorf("payload 解析失败: %w", err)
	}
	return &s, nil
}
