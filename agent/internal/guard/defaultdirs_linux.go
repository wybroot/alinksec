//go:build linux

package guard

// defaultDecoyDirs Linux 平台默认投放目录（/home/* 展开为各用户家目录）
func defaultDecoyDirs() []string {
	return []string{"/home/*", "/srv", "/opt"}
}
