//go:build windows

package collector

import (
	"errors"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const winSoftwarePackageLimit = 100000

type winUninstallReader interface {
	OpenRoot(path string) (winUninstallRoot, error)
}

type winUninstallRoot interface {
	ReadSubKeyNames() ([]string, error)
	OpenEntry(subKey string) (winUninstallEntry, error)
	Close() error
}

type winUninstallEntry interface {
	GetStringValue(name string) (string, error)
	Close() error
}

type windowsRegistryReader struct{}

type windowsRegistryRoot struct {
	key registry.Key
}

type windowsRegistryEntry struct {
	key registry.Key
}

func (windowsRegistryReader) OpenRoot(path string) (winUninstallRoot, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	return windowsRegistryRoot{key: k}, nil
}

func (r windowsRegistryRoot) ReadSubKeyNames() ([]string, error) {
	return r.key.ReadSubKeyNames(-1)
}

func (r windowsRegistryRoot) OpenEntry(subKey string) (winUninstallEntry, error) {
	sk, err := registry.OpenKey(r.key, subKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	return windowsRegistryEntry{key: sk}, nil
}

func (r windowsRegistryRoot) Close() error { return r.key.Close() }

func (e windowsRegistryEntry) GetStringValue(name string) (string, error) {
	val, _, err := e.key.GetStringValue(name)
	return val, err
}

func (e windowsRegistryEntry) Close() error { return e.key.Close() }

// collectWindows Windows 软件清单：注册表 Uninstall 项（含 32 位 WOW6432Node 视图）。
func collectSoftware(snap *pb.RptAssetSnapshot) {
	collectWindowsSoftware(snap, windowsRegistryReader{})
}

func classifyRegistryError(err error) string {
	if isPermissionError(err) {
		return "registry_permission_denied"
	}
	return "registry_query_failed"
}

func collectWindowsSoftware(snap *pb.RptAssetSnapshot, reader winUninstallReader) {
	snap.SoftwareInventory = &pb.SoftwareInventory{Status: pb.SoftwareInventory_FAILED, Source: "registry", Error: "registry_query_failed"}
	var software []*pb.SoftwareInfo
	const basePath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	paths := []string{basePath, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`}
	seen := map[string]bool{} // DisplayName + DisplayVersion 去重（避免 64/32 视图重复，同时保留同软件不同已装版本）

	for _, p := range paths {
		k, err := reader.OpenRoot(p)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				continue
			}
			snap.SoftwareInventory.Error = classifyRegistryError(err)
			return
		}
		subNames, err := k.ReadSubKeyNames()
		if err != nil {
			k.Close()
			snap.SoftwareInventory.Error = classifyRegistryError(err)
			return
		}
		if len(subNames) > winSoftwarePackageLimit {
			k.Close()
			snap.SoftwareInventory.Error = "registry_output_invalid_or_limited"
			return
		}
		for _, sub := range subNames {
			sk, err := k.OpenEntry(sub)
			if err != nil {
				if errors.Is(err, registry.ErrNotExist) {
					continue
				}
				k.Close()
				snap.SoftwareInventory.Error = classifyRegistryError(err)
				return
			}
			name, nameErr := sk.GetStringValue("DisplayName")
			if nameErr != nil && !errors.Is(nameErr, registry.ErrNotExist) {
				sk.Close()
				k.Close()
				snap.SoftwareInventory.Error = classifyRegistryError(nameErr)
				return
			}
			if strings.TrimSpace(name) == "" {
				sk.Close()
				continue
			}
			ver, verErr := sk.GetStringValue("DisplayVersion")
			if verErr != nil && !errors.Is(verErr, registry.ErrNotExist) {
				sk.Close()
				k.Close()
				snap.SoftwareInventory.Error = classifyRegistryError(verErr)
				return
			}
			vendor, vendorErr := sk.GetStringValue("Publisher")
			dateStr, dateErr := sk.GetStringValue("InstallDate") // YYYYMMDD
			if (vendorErr != nil && !errors.Is(vendorErr, registry.ErrNotExist)) ||
				(dateErr != nil && !errors.Is(dateErr, registry.ErrNotExist)) {
				errToClassify := vendorErr
				if errToClassify == nil || errors.Is(errToClassify, registry.ErrNotExist) {
					errToClassify = dateErr
				}
				sk.Close()
				k.Close()
				snap.SoftwareInventory.Error = classifyRegistryError(errToClassify)
				return
			}
			sk.Close()

			if strings.ContainsRune(name, '\x00') || len(name) > 255 ||
				strings.ContainsRune(ver, '\x00') || len(ver) > 255 ||
				strings.ContainsRune(vendor, '\x00') || len(vendor) > 255 ||
				len(software) >= winSoftwarePackageLimit {
				k.Close()
				snap.SoftwareInventory.Error = "registry_output_invalid_or_limited"
				return
			}

			key := name + "\x00" + ver
			if seen[key] {
				continue
			}
			seen[key] = true
			software = append(software, &pb.SoftwareInfo{
				Name:        name,
				Version:     ver,
				Vendor:      vendor,
				InstallTime: parseWinDate(dateStr),
				Source:      "registry",
			})
		}
		k.Close()
	}
	snap.Software = software
	snap.SoftwareInventory.Status = pb.SoftwareInventory_COMPLETE
	snap.SoftwareInventory.Error = ""
}

// parseWinDate "20240115" → epoch 毫秒；非法日历日期或解析失败返回 0
func parseWinDate(s string) int64 {
	if len(s) != 8 {
		return 0
	}
	t, err := time.ParseInLocation("20060102", s, time.Local)
	if err != nil || t.Year() < 1980 {
		return 0
	}
	return t.UnixMilli()
}
