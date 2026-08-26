//go:build windows

package collector

import (
	"strconv"
	"time"

	"golang.org/x/sys/windows/registry"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// collectWindows Windows 软件清单：注册表 Uninstall 项（含 32 位 WOW6432Node 视图）。
func collectSoftware(snap *pb.RptAssetSnapshot) {
	const basePath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	paths := []string{basePath, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`}
	seen := map[string]bool{} // DisplayName 去重（两个视图可能重复登记）

	for _, p := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p,
			registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		subNames, _ := k.ReadSubKeyNames(-1)
		for _, sub := range subNames {
			sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			if name == "" || seen[name] {
				sk.Close()
				continue
			}
			seen[name] = true
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			vendor, _, _ := sk.GetStringValue("Publisher")
			dateStr, _, _ := sk.GetStringValue("InstallDate") // YYYYMMDD
			snap.Software = append(snap.Software, &pb.SoftwareInfo{
				Name:        name,
				Version:     ver,
				Vendor:      vendor,
				InstallTime: parseWinDate(dateStr),
				Source:      "registry",
			})
			sk.Close()
		}
		k.Close()
	}
}

// parseWinDate "20240115" → epoch 毫秒；解析失败返回 0
func parseWinDate(s string) int64 {
	if len(s) != 8 {
		return 0
	}
	y, _ := strconv.Atoi(s[:4])
	mo, _ := strconv.Atoi(s[4:6])
	d, _ := strconv.Atoi(s[6:8])
	if y < 1980 || mo < 1 || mo > 12 || d < 1 || d > 31 {
		return 0
	}
	return time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.Local).UnixMilli()
}
