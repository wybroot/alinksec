//go:build linux

package baseline

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func checkIPv4Host(cs *CheckSpec) ItemResult {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return ItemResult{Error: true, Actual: ipv4HostPrefix(cs.Option), Message: "IPv4主机候选限定amd64/arm64"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	// /proc/sys/net and thread-self/ns/net must refer to the same calling thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return ipv4HostWithin(ctx, cs, ipv4HostRolePath, func() (ipv4HostSnapshot, error) { return readIPv4HostSnapshot(ctx, "/proc", true) })
}

func ipv4HostWithin(ctx context.Context, cs *CheckSpec, rolePath string, read func() (ipv4HostSnapshot, error)) ItemResult {
	failure := func(message string) ItemResult {
		return ItemResult{Error: true, Actual: ipv4HostPrefix(cs.Option), Message: message}
	}
	if !validIPv4Host(cs) {
		return failure("IPv4主机检查需固定查询和完整角色参考")
	}
	r := newPAMRead(cs.TimeoutMs)
	if deadline, ok := ctx.Deadline(); ok {
		r.deadline = deadline
	}
	defer r.close()
	// Verify every ancestor, not just the last directory, including no-follow,
	// numeric ownership, write permissions and access/default ACLs.
	var ancestors []string
	for dir := filepath.Dir(rolePath); ; dir = filepath.Dir(dir) {
		ancestors = append(ancestors, dir)
		if dir == "/" {
			break
		}
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		if _, err := r.open(ancestors[i], true); err != nil {
			return failure("IPv4角色声明父目录不可确认")
		}
		if err := trustedDiskInput(r.inputs[ancestors[i]], 0, 0); err != nil {
			return failure("IPv4角色声明父目录不可信")
		}
	}
	f, err := r.open(rolePath, false)
	if err != nil {
		return failure("需管理员明确声明当前Agent命名空间的IPv4非路由/对称路由角色")
	}
	if err := trustedDiskInput(r.inputs[rolePath], 0, 0); err != nil {
		return failure("IPv4角色声明UID/GID、权限、链接或ACL不可信")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || string(raw) != ipv4HostRole {
		return failure("IPv4角色未声明、未支持或不适用；不得由参数值推断主机角色")
	}
	return observeIPv4Host(ctx, cs, read, func() error {
		if err := r.stable(); err != nil {
			return fmt.Errorf("IPv4角色声明在读取期间变化或超时")
		}
		for _, input := range r.inputs {
			if err := trustedDiskInput(input, 0, 0); err != nil {
				return err
			}
		}
		return nil
	})
}

// No path or filesystem override is exposed by CheckSpec. The parameters are
// solely for bounded-reader fault injection; production always requires procfs.
func readIPv4HostSnapshot(ctx context.Context, proc string, requireProc bool) (ipv4HostSnapshot, error) {
	s := ipv4HostSnapshot{Interfaces: map[string]ipv4HostValues{}, Identities: map[string]string{}}
	var namespace unix.Stat_t
	if err := unix.Stat(filepath.Join(proc, "thread-self/ns/net"), &namespace); err != nil {
		return s, fmt.Errorf("IPv4当前线程网络命名空间不可查询")
	}
	s.Namespace = fmt.Sprintf("%d:%d", namespace.Dev, namespace.Ino)
	// Keep all directory and value descriptors until path/namespace rechecks.
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
	if !requireProc {
		uid, gid = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	open := func(parent int, name, path string, directory bool) (*os.File, error) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("IPv4读取超时")
		}
		flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, name, flags, 0)
		if err != nil {
			return nil, fmt.Errorf("IPv4路径缺失、不可读或为链接: %s", path)
		}
		f := os.NewFile(uintptr(fd), path)
		var st unix.Stat_t
		var fs unix.Statfs_t
		if err := unix.Fstat(fd, &st); err != nil {
			f.Close()
			return nil, err
		}
		kind := uint32(unix.S_IFREG)
		if directory {
			kind = unix.S_IFDIR
		}
		if st.Mode&unix.S_IFMT != kind || st.Mode&0022 != 0 || st.Uid != uid || st.Gid != gid ||
			(!directory && (st.Nlink != 1 || st.Size > 64)) || requireProc && (unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC) {
			f.Close()
			return nil, fmt.Errorf("IPv4路径类型、属主、权限或procfs身份不可确认")
		}
		inputs = append(inputs, input{path, f, st})
		s.Identities[path] = fmt.Sprintf("%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Mode, st.Uid, st.Gid)
		return f, nil
	}
	root, err := open(unix.AT_FDCWD, proc, proc, true)
	if err != nil {
		return s, err
	}
	dir, path := root, proc
	for _, name := range []string{"sys", "net", "ipv4"} {
		path = filepath.Join(path, name)
		dir, err = open(int(dir.Fd()), name, path, true)
		if err != nil {
			return s, err
		}
	}
	readValue := func(parent *os.File, name string, maxValue int) (int, error) {
		f, err := open(int(parent.Fd()), name, filepath.Join(parent.Name(), name), false)
		if err != nil {
			return 0, err
		}
		raw, err := io.ReadAll(io.LimitReader(f, 65))
		if err != nil || ctx.Err() != nil || len(raw) != 2 || raw[1] != '\n' || raw[0] < '0' || int(raw[0]-'0') > maxValue {
			return 0, fmt.Errorf("IPv4参数缺失、格式未知、超限或读取超时")
		}
		return int(raw[0] - '0'), nil
	}
	s.IPForward, err = readValue(dir, "ip_forward", 1)
	if err != nil {
		return s, err
	}
	conf, err := open(int(dir.Fd()), "conf", filepath.Join(dir.Name(), "conf"), true)
	if err != nil {
		return s, err
	}
	names, err := conf.Readdirnames(ipv4HostMaxInterfaces + 3)
	if err != nil && err != io.EOF || len(names) > ipv4HostMaxInterfaces+2 {
		return s, fmt.Errorf("IPv4接口目录读取失败或超过16个接口")
	}
	sort.Strings(names)
	for _, name := range names {
		if !ipv4HostInterfaceName.MatchString(name) {
			return s, fmt.Errorf("IPv4接口名称未支持")
		}
		iface, err := open(int(conf.Fd()), name, filepath.Join(conf.Name(), name), true)
		if err != nil {
			return s, err
		}
		rp, err := readValue(iface, "rp_filter", 2)
		if err != nil {
			return s, err
		}
		forward, err := readValue(iface, "forwarding", 1)
		if err != nil {
			return s, err
		}
		s.Interfaces[name] = ipv4HostValues{rp, forward}
	}
	if _, err := conf.Seek(0, 0); err != nil {
		return s, err
	}
	again, err := conf.Readdirnames(ipv4HostMaxInterfaces + 3)
	if err != nil && err != io.EOF {
		return s, err
	}
	sort.Strings(again)
	if strings.Join(names, "\x00") != strings.Join(again, "\x00") {
		return s, fmt.Errorf("IPv4接口集合在读取期间变化")
	}
	for _, input := range inputs {
		var fdStat, pathStat unix.Stat_t
		if ctx.Err() != nil || unix.Fstat(int(input.file.Fd()), &fdStat) != nil || unix.Lstat(input.path, &pathStat) != nil ||
			fdStat.Dev != input.stat.Dev || fdStat.Ino != input.stat.Ino || pathStat.Dev != fdStat.Dev || pathStat.Ino != fdStat.Ino ||
			fdStat.Mode != input.stat.Mode || fdStat.Uid != input.stat.Uid || fdStat.Gid != input.stat.Gid || pathStat.Mode != fdStat.Mode {
			return s, fmt.Errorf("IPv4路径在读取期间变化或超时")
		}
	}
	var after unix.Stat_t
	if unix.Stat(filepath.Join(proc, "thread-self/ns/net"), &after) != nil || after.Dev != namespace.Dev || after.Ino != namespace.Ino {
		return s, fmt.Errorf("IPv4网络命名空间在读取期间变化")
	}
	return s, nil
}
