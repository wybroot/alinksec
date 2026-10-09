//go:build linux

package baseline

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// Trusted metadata supplements the bounded, no-follow reader and its final
// descriptor/path stability check. Callers still declare their product scope.
func trustedDiskInput(input pamInput, uid, gid uint32) error {
	s := input.info.Sys().(*syscall.Stat_t)
	if s.Uid != uid || s.Gid != gid || s.Mode&0022 != 0 || input.info.Mode().IsRegular() && s.Nlink != 1 {
		return fmt.Errorf("不可信磁盘输入")
	}
	attrs := []string{"system.posix_acl_access"}
	if input.info.IsDir() {
		attrs = append(attrs, "system.posix_acl_default")
	}
	for _, attr := range attrs {
		size, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", input.file.Fd()), attr, nil)
		if err != nil && err != unix.ENODATA || size > 0 {
			return fmt.Errorf("磁盘输入ACL未确认")
		}
	}
	return nil
}
