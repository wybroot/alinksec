//go:build linux

package baseline

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// O_PATH never reads log contents, opens devices or blocks on a FIFO. Every
// component is opened relative to a held directory, without following links.
func openLogPath(root, target string) (*os.File, []unix.Stat_t, error) {
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("无法打开日志路径根目录")
	}
	var chain []unix.Stat_t
	for _, part := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return nil, nil, fmt.Errorf("日志路径无效")
		}
		var parent unix.Stat_t
		if err := unix.Fstat(fd, &parent); err != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(fd)
			return nil, nil, fmt.Errorf("日志路径包含链接或非目录组件")
		}
		chain = append(chain, parent)
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, nil, fmt.Errorf("日志路径缺失或无法取得元数据")
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), target), chain, nil
}

func sameLogMetadata(a, b *syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid &&
		a.Gid == b.Gid && a.Nlink == b.Nlink && a.Ctim == b.Ctim
}

func checkLogMetadata(cs *CheckSpec) ItemResult {
	return logMetadataWithin(cs, "/", "/etc/group")
}

// Tests use a private root; production always uses the real fixed paths.
func logMetadataWithin(cs *CheckSpec, root, groupPath string) ItemResult {
	prefix := "scope=fixed-log-path target=" + cs.Target
	fail := func(message string) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: message} }
	perm, group := logMetadataPolicy(cs.Target)
	if perm == "" || cs.Operator != "subset" || cs.Perm != perm || cs.Owner != "0" || cs.Group != group {
		return fail("日志元数据参考定义无效")
	}
	deadline := time.Now().Add(time.Duration(cs.TimeoutMs) * time.Millisecond)
	f, parents, err := openLogPath(root, cs.Target)
	if err != nil {
		return fail(err.Error())
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fail("无法取得日志元数据")
	}
	directory := cs.Target == "/var/log/audit"
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fail("日志目标类型不符或为链接；审计目标需目录，btmp/wtmp 需普通文件")
	}
	st := info.Sys().(*syscall.Stat_t)
	if !directory && st.Nlink != 1 {
		return fail("日志文件存在硬链接或正在被替换，超出单路径参考范围")
	}
	mode := st.Mode & 07777
	kind, defaultACL := "regular", "n/a"
	if directory {
		kind, defaultACL = "directory", "none"
	}
	prefix += fmt.Sprintf(" kind=%s mode=%04o uid=%d gid=%d", kind, mode, st.Uid, st.Gid)
	attributes := []string{"system.posix_acl_access"}
	if directory {
		attributes = append(attributes, "system.posix_acl_default")
	}
	for _, name := range attributes {
		size, aclErr := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), name, nil)
		if aclErr != nil && aclErr != unix.ENODATA || size > 0 {
			return fail("存在访问/默认 ACL 或无法确认 ACL；本参考不判断完整访问权限")
		}
	}
	expectedGID := uint32(0)
	if group == "utmp" {
		expectedGID, err = identityGroup(groupPath, group, deadline)
		if err != nil {
			return fail(err.Error())
		}
	}
	// Reopen from the root to detect replacement of the target or its parents.
	current, currentParents, err := openLogPath(root, cs.Target)
	if err != nil {
		return fail("日志路径在检查期间发生变化")
	}
	defer current.Close()
	currentInfo, err := current.Stat()
	after, afterErr := f.Stat()
	stable := err == nil && afterErr == nil && len(parents) == len(currentParents)
	if stable {
		stable = sameLogMetadata(st, after.Sys().(*syscall.Stat_t)) && sameLogMetadata(st, currentInfo.Sys().(*syscall.Stat_t))
		for i := range parents {
			stable = stable && parents[i].Dev == currentParents[i].Dev && parents[i].Ino == currentParents[i].Ino
		}
	}
	if !stable || time.Now().After(deadline) {
		return fail("日志路径/元数据在检查期间发生变化或检查超时，请重试")
	}
	allowed, _ := strconv.ParseUint(perm, 8, 16)
	prefix += fmt.Sprintf(" access_acl=none default_acl=%s allowed_mode=%s expected_uid=0 expected_gid=%d", defaultACL, perm, expectedGID)
	passed := mode & ^uint32(allowed) == 0 && st.Uid == 0 && st.Gid == expectedGID
	result := ItemResult{Passed: passed, Actual: prefix}
	if !passed {
		result.Message = "日志路径权限超出允许位，或数值属主/属组不满足参考策略"
	}
	return result
}
