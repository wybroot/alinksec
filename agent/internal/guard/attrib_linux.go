//go:build linux

package guard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

func (g *Guard) configureAttribution()          {} // Linux attribution remains separate.
func (g *Guard) runAttribution(context.Context) {}
func (g *Guard) reportAttributionStatus()       {}
func (g *Guard) attribute(files []string) *suspectProc {
	if p := attributeByOpenFD(files); p != nil {
		return p
	}
	return attributeByRecency(g.excluded)
}
func (g *Guard) attributeResponse(files []string, _ time.Time, _ map[string]any) (*suspectProc, func() error) {
	p := g.attribute(files)
	return p, func() error {
		if p != nil && KillProcess(p.Pid) {
			return nil
		}
		return fmt.Errorf("process termination failed")
	}
}

/* Linux 归因：/proc/<pid>/fd/* readlink 反查持有受影响目录/诱饵文件句柄的进程。
 * 加密进行中通常持有大量目标文件写句柄 → 高置信；失败回退启发式（respond.go）。 */

func attributeByOpenFD(files []string) *suspectProc {
	if len(files) == 0 {
		return nil
	}
	// 受影响文件所在目录集合
	dirs := map[string]bool{}
	for _, f := range files {
		dirs[filepath.Dir(f)] = true
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		pid, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if dirs[filepath.Dir(target)] {
				p, err := process.NewProcess(int32(pid))
				if err == nil {
					return takeForensics(p)
				}
			}
		}
	}
	return nil
}
