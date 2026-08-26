//go:build windows

package fixer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
	"golang.org/x/sys/windows"
)

// freeDiskMB 临时目录所在盘余量
func freeDiskMB() (float64, error) {
	var free, total, avail uint64
	err := windows.GetDiskFreeSpaceEx(windows.StringToUTF16Ptr(os.TempDir()), &free, &total, &avail)
	if err != nil {
		u, e := disk.Usage(os.TempDir())
		if e != nil {
			return 0, e
		}
		return float64(u.Free) / (1 << 20), nil
	}
	return float64(free) / (1 << 20), nil
}

// queryPkgVersion Windows 补丁（KB）安装查询：dism /online /get-packages 精确匹配成本高，
// 走注册表 QuickFixInstalled 太慢；返回空 = 无法查询（复核由平台重扫承担）
func queryPkgVersion(pkg string) string {
	return ""
}

// installPatch Windows：wusa /quiet /norestart；退出码 3010 = 需重启（算成功）
func installPatch(p *PkgPayload, tmpFile string, addLog func(string, ...any)) (reboot bool, err error) {
	if p.RepoType != "msu" {
		return false, fmt.Errorf("Windows 不支持补丁类型 %s", p.RepoType)
	}
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "wusa.exe")
	addLog("执行: wusa %s /quiet /norestart", filepath.Base(tmpFile))
	cmd := exec.Command(exe, tmpFile, "/quiet", "/norestart")
	err = cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 3010 {
			addLog("补丁安装成功，需重启生效（已标记 reboot_required）")
			return true, nil
		}
		return false, fmt.Errorf("wusa: %w", err)
	}
	// 部分补丁装完即要求重启：统一标记由客户窗口内处理
	addLog("补丁安装完成（如需重启由平台展示待重启清单）")
	return true, nil
}

func filepathBase(p string) string { return filepath.Base(p) }

func tailOutput(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 400 {
		s = "..." + s[len(s)-400:]
	}
	return s
}

func stringsEqualFold(a, b string) bool { return strings.EqualFold(a, b) }

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
