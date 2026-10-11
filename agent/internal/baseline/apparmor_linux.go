//go:build linux

package baseline

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func checkAppArmor(cs *CheckSpec) ItemResult {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return ItemResult{Error: true, Actual: appArmorPrefix(), Message: "AppArmor候选限定Linux amd64/arm64"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	// Namespace introspection belongs to the calling thread's current label.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return observeAppArmor(ctx, cs, func() (appArmorSnapshot, error) { return readAppArmorSnapshot(ctx, "/sys", true) })
}

// The root/identity switch is exclusively for reader fault injection. CheckSpec
// cannot select files, mounts, namespace paths or alternate security mechanisms.
func readAppArmorSnapshot(ctx context.Context, root string, requireKernel bool) (appArmorSnapshot, error) {
	return readAppArmorInputs(ctx, root, requireKernel, nil)
}

func readAppArmorInputs(ctx context.Context, root string, requireKernel bool, beforeStable func()) (appArmorSnapshot, error) {
	s := appArmorSnapshot{Values: map[string]string{}, Identities: map[string]string{}}
	type input struct {
		path string
		file *os.File
		stat unix.Stat_t
	}
	var inputs []input
	defer func() {
		for _, v := range inputs {
			v.file.Close()
		}
	}()
	uid, gid := uint32(0), uint32(0)
	if !requireKernel {
		uid, gid = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	open := func(parent int, name, path string, directory bool, magic int64) (*os.File, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, name, flags, 0)
		if err != nil {
			return nil, fmt.Errorf("AppArmor接口不可读取")
		}
		f := os.NewFile(uintptr(fd), path)
		var st unix.Stat_t
		var fs unix.Statfs_t
		kind := uint32(unix.S_IFREG)
		if directory {
			kind = unix.S_IFDIR
		}
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != kind || st.Uid != uid || st.Gid != gid || st.Mode&0022 != 0 ||
			unix.Fstatfs(fd, &fs) != nil || requireKernel && fs.Type != magic || !directory && (!requireKernel && st.Nlink != 1 || st.Size > appArmorMaxBytes) {
			f.Close()
			return nil, fmt.Errorf("AppArmor接口类型、属主、权限或文件系统身份不可确认")
		}
		inputs = append(inputs, input{path, f, st})
		s.Identities[path] = fmt.Sprintf("%d:%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Mode, st.Uid, st.Gid, fs.Type)
		return f, nil
	}
	base, err := open(unix.AT_FDCWD, root, root, true, unix.SYSFS_MAGIC)
	if err != nil {
		return s, err
	}
	directory := func(parent *os.File, name string, magic int64) (*os.File, error) {
		return open(int(parent.Fd()), name, filepath.Join(parent.Name(), name), true, magic)
	}
	read := func(parent *os.File, name, key string, limit int, magic int64) error {
		f, err := open(int(parent.Fd()), name, filepath.Join(parent.Name(), name), false, magic)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
		if err != nil || len(raw) > limit || ctx.Err() != nil {
			return fmt.Errorf("AppArmor接口读取失败、超限或超时")
		}
		s.Values[key] = string(raw)
		return nil
	}
	module, err := directory(base, "module", unix.SYSFS_MAGIC)
	if err != nil {
		return s, err
	}
	aaModule, err := directory(module, "apparmor", unix.SYSFS_MAGIC)
	if err != nil {
		return s, err
	}
	parameters, err := directory(aaModule, "parameters", unix.SYSFS_MAGIC)
	if err != nil {
		return s, err
	}
	kernel, err := directory(base, "kernel", unix.SYSFS_MAGIC)
	if err != nil {
		return s, err
	}
	security, err := directory(kernel, "security", unix.SECURITYFS_MAGIC)
	if err != nil {
		return s, err
	}
	if err := read(parameters, "enabled", "enabled", 2, unix.SYSFS_MAGIC); err != nil {
		return s, err
	}
	if err := read(security, "lsm", "lsm", 1024, unix.SECURITYFS_MAGIC); err != nil {
		return s, err
	}
	present, err := appArmorLSM(s.Values["lsm"])
	if err != nil {
		return s, err
	}
	if s.Values["enabled"] == "Y\n" && present {
		if err := read(parameters, "mode", "mode", 32, unix.SYSFS_MAGIC); err != nil {
			return s, err
		}
		aa, err := directory(security, "apparmor", unix.SECURITYFS_MAGIC)
		if err != nil {
			return s, err
		}
		for _, v := range []struct{ name, key string }{{".ns_level", "level"}, {".stacked", "stacked"}, {".ns_stacked", "ns_stacked"}} {
			if err := read(aa, v.name, v.key, 16, unix.SECURITYFS_MAGIC); err != nil {
				return s, err
			}
		}
		if err := read(aa, "profiles", "profiles", appArmorMaxBytes, unix.SECURITYFS_MAGIC); err != nil {
			return s, err
		}
	}
	if beforeStable != nil {
		beforeStable()
	}
	for _, input := range inputs {
		var fdStat, pathStat unix.Stat_t
		if ctx.Err() != nil || unix.Fstat(int(input.file.Fd()), &fdStat) != nil || unix.Lstat(input.path, &pathStat) != nil ||
			fdStat.Dev != input.stat.Dev || fdStat.Ino != input.stat.Ino || pathStat.Dev != fdStat.Dev || pathStat.Ino != fdStat.Ino ||
			fdStat.Mode != input.stat.Mode || fdStat.Uid != input.stat.Uid || fdStat.Gid != input.stat.Gid || pathStat.Mode != fdStat.Mode || pathStat.Uid != fdStat.Uid || pathStat.Gid != fdStat.Gid ||
			fdStat.Mtim != input.stat.Mtim || fdStat.Ctim != input.stat.Ctim {
			return s, fmt.Errorf("AppArmor接口在读取期间变化或超时")
		}
	}
	return s, nil
}
