//go:build windows

package guard

// defaultDecoyDirs Windows 平台默认投放目录（公共文档/公共桌面）
func defaultDecoyDirs() []string {
	return []string{
		`C:\Users\Public\Documents`,
		`C:\Users\Public\Desktop`,
	}
}
