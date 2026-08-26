// Package virusscan 扫描路径（docs/05 §1.3）：
// 快扫关键路径与全盘根，按平台区分。
package virusscan

import (
	"os"
	"path/filepath"
	"runtime"
)

// quickScanRoots 快速扫描路径（分钟级）：临时目录 / 用户目录 / 自启动目录
func quickScanRoots() []string {
	var roots []string
	if runtime.GOOS == "windows" {
		for _, e := range []string{"TEMP", "TMP", "USERPROFILE", "ProgramData", "APPDATA", "LOCALAPPDATA"} {
			if v := os.Getenv(e); v != "" {
				roots = append(roots, v)
			}
		}
	} else {
		roots = []string{"/tmp", "/var/tmp", "/dev/shm", "/root", "/home", "/etc/cron.d", "/var/spool/cron"}
	}
	return dedupExists(roots)
}

// fullScanRoots 全盘扫描根：Windows 盘符 / Linux 挂载点
func fullScanRoots() []string {
	if runtime.GOOS == "windows" {
		var roots []string
		for c := 'C'; c <= 'Z'; c++ {
			root := string(c) + `:\`
			if st, err := os.Stat(root); err == nil && st.IsDir() {
				roots = append(roots, root)
			}
		}
		return roots
	}
	return dedupExists([]string{"/"})
}

func dedupExists(roots []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range roots {
		r = filepath.Clean(r)
		if seen[r] {
			continue
		}
		if _, err := os.Stat(r); err == nil {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
