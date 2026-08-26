// Package baseline 基线核查引擎：解释执行服务端下发的 check JSON（docs/04 §3.2）。
//
// 支持四类检查（与 t_baseline_item.check 种子一致）：
//   - file_content：目标文件任意行匹配 regex
//   - file_line：   目标文件行级断言（regex / contains / not_contains）
//   - file_perm：   文件权限/属主断言（Linux）
//   - cmd_output：  命令执行输出断言（eq / ne / contains / not_contains / regex）
package baseline

import (
	"encoding/json"
	"fmt"
)

// CheckSpec check JSON 反序列化结构（字段按四类检查取并集，多余字段忽略）
type CheckSpec struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	Regex   string `json:"regex"`
	Operator string `json:"operator"`
	Expected string `json:"expected"`
	Cmd     string `json:"cmd"`
	Perm    string `json:"perm"`
	Owner   string `json:"owner"`
	Group   string `json:"group"`
	TimeoutMs int  `json:"timeout_ms"`
}

// ParseCheck 解析 check JSON；type 缺失或无法解析时返回错误（该项按失败落库）
func ParseCheck(checkJSON string) (*CheckSpec, error) {
	var s CheckSpec
	if err := json.Unmarshal([]byte(checkJSON), &s); err != nil {
		return nil, fmt.Errorf("check JSON 解析失败: %w", err)
	}
	switch s.Type {
	case "file_content", "file_line", "file_perm", "cmd_output":
	default:
		return nil, fmt.Errorf("不支持的检查类型: %q", s.Type)
	}
	if s.TimeoutMs <= 0 {
		s.TimeoutMs = 5000
	}
	return &s, nil
}
