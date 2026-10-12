//go:build windows

package collector

import (
	"errors"
	"strconv"
	"time"

	"golang.org/x/sys/windows/registry"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// collectWindows Windows 软件清单：注册表 Uninstall 项（含 32 位 WOW6432Node 视图）。
func collectSoftware(snap *pb.RptAssetSnapshot) {
	snap.SoftwareInventory = &pb.SoftwareInventory{Status: pb.SoftwareInventory_FAILED, Source: "registry", Error: "registry_query_failed"}
	var software []*pb.SoftwareInfo
	const basePath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	paths := []string{basePath, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`}
	seen := map[string]bool{} // DisplayName 去重（两个视图可能重复登记）

	for _, p := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p,
			registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				continue
			}
			return
		}
		subNames, err := k.ReadSubKeyNames(-1)
		if err != nil || len(subNames) > 100000 {
			k.Close()
			return
		}
		for _, sub := range subNames {
			sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE)
			if err != nil {
				k.Close()
				return
			}
			name, _, nameErr := sk.GetStringValue("DisplayName")
			if nameErr != nil && !errors.Is(nameErr, registry.ErrNotExist) {
				sk.Close()
				k.Close()
				return
			}
			if name == "" || seen[name] {
				sk.Close()
				continue
			}
			seen[name] = true
			ver, _, verErr := sk.GetStringValue("DisplayVersion")
			if verErr != nil && !errors.Is(verErr, registry.ErrNotExist) {
				sk.Close()
				k.Close()
				return
			}
			vendor, _, vendorErr := sk.GetStringValue("Publisher")
			dateStr, _, dateErr := sk.GetStringValue("InstallDate") // YYYYMMDD
			if (vendorErr != nil && !errors.Is(vendorErr, registry.ErrNotExist)) ||
				(dateErr != nil && !errors.Is(dateErr, registry.ErrNotExist)) || len(software) >= 100000 {
				sk.Close()
				k.Close()
				return
			}
			software = append(software, &pb.SoftwareInfo{
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
	snap.Software = software
	snap.SoftwareInventory.Status = pb.SoftwareInventory_COMPLETE
	snap.SoftwareInventory.Error = ""
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
