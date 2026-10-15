//go:build windows

package guard

import "fmt"

// Legacy netsh isolation overwrote profile defaults without recording their
// original values. Guessing defaults would silently weaken administrator policy.
// New isolation uses owned WFP dynamic filters in internal/isolation instead.
func restorePlatform() error {
	return fmt.Errorf("旧版隔离未记录原有 Windows 防火墙策略；请管理员恢复原策略并移除 isolated.json 后重试")
}
