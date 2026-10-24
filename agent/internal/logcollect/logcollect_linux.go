//go:build linux

package logcollect

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
	"time"
)

func pollInterval() time.Duration { return 5 * time.Second }
func (c *Collector) pollOnce() {
	c.tailFile("/var/log/secure", "secure")
	c.tailFile("/var/log/auth.log", "auth.log")
}
func openLog(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
func fileIdentity(st os.FileInfo) string {
	v := st.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", v.Dev, v.Ino)
}
