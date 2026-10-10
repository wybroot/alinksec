//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var programLibcVersions = regexp.MustCompile(`^ii \tlibc-bin\t2\.39-0ubuntu8(?:\.[0-9]+)?\nii \tlibc6\t2\.39-0ubuntu8(?:\.[0-9]+)?$`)

type programFilesPaths struct {
	root, arch string
	uid, gid   uint32
}

func (p programFilesPaths) path(logical string) string {
	return filepath.Join(p.root, strings.TrimPrefix(logical, "/"))
}
func queryProgramLibcVersions(ctx context.Context, timeout int) ItemResult {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "--show", "--showformat=${db:Status-Abbrev}\t${Package}\t${Version}\n", "--", "libc-bin", "libc6:"+runtime.GOARCH)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	return collectBaselineCommand(ctx, cmd, timeout)
}
func checkProgramFiles(cs *CheckSpec) ItemResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	return programFilesWithin(ctx, cs, programFilesPaths{"/", runtime.GOARCH, 0, 0}, queryProgramLibcVersions)
}
func programTrustedOpen(r *pamRead, p programFilesPaths, logical string, directory bool) (*os.File, error) {
	// Each ancestor is opened without following links and held through stability
	// checks. Fixture roots are isolated replicas; production starts at '/'.
	var parents []string
	for dir := filepath.Dir(logical); ; dir = filepath.Dir(dir) {
		parents = append(parents, dir)
		if dir == "/" {
			break
		}
	}
	for i := len(parents) - 1; i >= 0; i-- {
		path := p.path(parents[i])
		if _, ok := r.inputs[path]; ok {
			continue
		}
		if _, err := r.open(path, true); err != nil {
			return nil, err
		}
		if err := trustedDiskInput(r.inputs[path], p.uid, p.gid); err != nil {
			return nil, err
		}
	}
	path := p.path(logical)
	if value, ok := r.inputs[path]; ok {
		return value.file, nil
	}
	f, err := r.open(path, directory)
	if err != nil {
		return nil, err
	}
	if err := trustedDiskInput(r.inputs[path], p.uid, p.gid); err != nil {
		return nil, err
	}
	return f, nil
}
func programReadSmall(ctx context.Context, r *pamRead, p programFilesPaths, logical string) (string, error) {
	f, err := programTrustedOpen(r, p, logical, false)
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	r.bytes += len(raw)
	if err != nil || len(raw) > 64*1024 || r.bytes > 256*1024 || ctx.Err() != nil {
		return "", fmt.Errorf("程序输入读取失败、64KiB/256KiB超限或超时")
	}
	return string(raw), nil
}
func programDirectoryNames(ctx context.Context, f *os.File, limit int) ([]string, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("程序目录查询超时")
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(limit + 1)
	if err != nil && err != io.EOF || len(names) > limit {
		return nil, fmt.Errorf("程序目录枚举失败或超限")
	}
	for _, name := range names {
		if !programInputName(name) {
			return nil, fmt.Errorf("程序目录名称超出可完整观察范围")
		}
	}
	sort.Strings(names)
	return names, nil
}
func programFilesWithin(ctx context.Context, cs *CheckSpec, p programFilesPaths, query func(context.Context, int) ItemResult) ItemResult {
	prefix := programFilesPrefix(cs.Option)
	failure := func(err error) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: err.Error()} }
	if !validProgramFiles(cs) || p.arch != "amd64" && p.arch != "arm64" {
		return failure(fmt.Errorf("程序文件检查需Ubuntu24 amd64/arm64完整固定参考"))
	}
	first := query(ctx, cs.TimeoutMs)
	if first.Error || !programLibcVersions.MatchString(first.Actual) {
		return failure(fmt.Errorf("需完整安装Ubuntu24 libc-bin/libc6 2.39-0ubuntu8系列"))
	}
	r := newPAMRead(cs.TimeoutMs)
	if deadline, ok := ctx.Deadline(); ok {
		r.deadline = deadline
	}
	defer r.close()
	var result ItemResult
	var err error
	if cs.Option == "linker_metadata" {
		result, err = observeLinkerMetadata(ctx, r, p)
	} else {
		result, err = observePrivilegedReference(ctx, r, p, cs.Expected)
	}
	if err != nil {
		return failure(err)
	}
	last := query(ctx, cs.TimeoutMs)
	if last.Error || last.Actual != first.Actual || ctx.Err() != nil {
		return failure(fmt.Errorf("程序组件版本变化、查询失败或超过共同截止时间"))
	}
	if err := r.stable(); err != nil {
		return failure(fmt.Errorf("程序配置/清单/父目录在查询期间变化或超时"))
	}
	for _, input := range r.inputs {
		if err := trustedDiskInput(input, p.uid, p.gid); err != nil {
			return failure(err)
		}
	}
	result.Actual = prefix + "arch=" + p.arch + " libc_versions_sha256=" + fmt.Sprintf("%x", sha256.Sum256([]byte(first.Actual))) + " " + result.Actual
	return result
}
func linkerLines(raw string, main bool) error {
	if !utf8.ValidString(raw) || !strings.HasSuffix(raw, "\n") || strings.Count(raw, "\n") > 1024 {
		return fmt.Errorf("链接器配置UTF8/完整行/行数未支持")
	}
	includes := 0
	for _, line := range strings.Split(raw, "\n") {
		if len(line) > 1024 || strings.ContainsAny(line, "\r\x00") {
			return fmt.Errorf("链接器配置物理行超限或含控制字符")
		}
		line = strings.Trim(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if main && line == "include /etc/ld.so.conf.d/*.conf" {
			includes++
			continue
		}
		if !strings.HasPrefix(line, "/") || filepath.Clean(line) != line || strings.ContainsAny(line, " \t\\$'\"*?[];=`#") {
			return fmt.Errorf("链接器配置活动语法/包含范围未支持")
		}
		for _, c := range []byte(line) {
			if c < 33 || c > 126 {
				return fmt.Errorf("链接器配置路径字符未支持")
			}
		}
	}
	if main && includes != 1 {
		return fmt.Errorf("链接器入口需唯一固定ld.so.conf.d/*.conf包含")
	}
	return nil
}
func observeLinkerMetadata(ctx context.Context, r *pamRead, p programFilesPaths) (ItemResult, error) {
	main, err := programReadSmall(ctx, r, p, "/etc/ld.so.conf")
	if err != nil {
		return ItemResult{}, err
	}
	if err := linkerLines(main, true); err != nil {
		return ItemResult{}, err
	}
	parts, err := programTrustedOpen(r, p, "/etc/ld.so.conf.d", true)
	if err != nil {
		return ItemResult{}, err
	}
	names, err := programDirectoryNames(ctx, parts, 128)
	if err != nil {
		return ItemResult{}, err
	}
	selected := 0
	passed := true
	for _, name := range names {
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		selected++
		if selected > 32 {
			return ItemResult{}, fmt.Errorf("链接器包含片段超过32")
		}
		raw, err := programReadSmall(ctx, r, p, "/etc/ld.so.conf.d/"+name)
		if err != nil {
			return ItemResult{}, err
		}
		if err := linkerLines(raw, false); err != nil {
			return ItemResult{}, err
		}
	}
	for _, input := range r.inputs {
		limit := os.FileMode(0644)
		if input.info.IsDir() {
			limit = 0755
		}
		if input.info.Mode().Perm()&^limit != 0 {
			passed = false
		}
	}
	again, err := programDirectoryNames(ctx, parts, 128)
	if err != nil || !reflect.DeepEqual(names, again) {
		return ItemResult{}, fmt.Errorf("链接器片段目录在读取期间变化")
	}
	message := ""
	if !passed {
		message = "链接器配置或目录元数据未满足有限权限上限参考"
	}
	return ItemResult{Passed: passed, Actual: fmt.Sprintf("entry=/etc/ld.so.conf included_conf=%d config_inputs=%d permissions_reference_match=%t", selected, len(r.inputs), passed), Message: message}, nil
}

type programStamp struct {
	Dev, Ino       uint64
	Mode, UID, GID uint32
	Links          uint64
	Size           int64
	Mtime, Ctime   unix.Timespec
}

func programFileStamp(s unix.Stat_t) programStamp {
	return programStamp{uint64(s.Dev), s.Ino, s.Mode, s.Uid, s.Gid, uint64(s.Nlink), s.Size, s.Mtim, s.Ctim}
}

type privilegedSnapshot struct {
	Entries                                           []privilegedEntry
	Stamps                                            map[string]programStamp
	Names                                             map[string][]string
	ExcludedLinks, ExcludedDirectories, ExcludedOther int
	Bytes                                             int64
}

func scanPrivileged(ctx context.Context, r *pamRead, p programFilesPaths) (privilegedSnapshot, error) {
	s := privilegedSnapshot{Stamps: map[string]programStamp{}, Names: map[string][]string{}}
	for _, logical := range []string{"/usr/bin", "/usr/sbin"} {
		dir, err := programTrustedOpen(r, p, logical, true)
		if err != nil {
			return s, err
		}
		names, err := programDirectoryNames(ctx, dir, 4096)
		if err != nil {
			return s, err
		}
		s.Names[logical] = names
		for _, name := range names {
			if ctx.Err() != nil {
				return s, fmt.Errorf("SUID/SGID枚举超过共同截止时间")
			}
			var st unix.Stat_t
			if unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return s, fmt.Errorf("SUID/SGID条目元数据读取失败")
			}
			key := logical + "/" + name
			s.Stamps[key] = programFileStamp(st)
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFLNK:
				s.ExcludedLinks++
				continue
			case unix.S_IFDIR:
				s.ExcludedDirectories++
				continue
			case unix.S_IFREG:
			default:
				s.ExcludedOther++
				continue
			}
			if st.Mode&06000 == 0 {
				continue
			}
			if len(s.Entries) >= 128 {
				return s, fmt.Errorf("SUID/SGID选中普通文件超过128")
			}
			if st.Nlink != 1 || st.Size < 0 || st.Size > 8*1024*1024 || s.Bytes+st.Size > 16*1024*1024 {
				return s, fmt.Errorf("SUID/SGID选中文件硬链接或单/总大小超限")
			}
			fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return s, fmt.Errorf("SUID/SGID选中文件不可读")
			}
			f := os.NewFile(uintptr(fd), key)
			entry, bytes, err := hashPrivilegedInput(ctx, f, st, key)
			f.Close()
			if err != nil {
				return s, err
			}
			s.Bytes += bytes
			if s.Bytes > 16*1024*1024 {
				return s, fmt.Errorf("SUID/SGID单次内容读取超过16MiB")
			}
			s.Entries = append(s.Entries, entry)
		}
		again, err := programDirectoryNames(ctx, dir, 4096)
		if err != nil || !reflect.DeepEqual(names, again) {
			return s, fmt.Errorf("SUID/SGID目录成员在枚举期间变化")
		}
		for _, name := range names {
			var after unix.Stat_t
			if ctx.Err() != nil || unix.Fstatat(int(dir.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || programFileStamp(after) != s.Stamps[logical+"/"+name] {
				return s, fmt.Errorf("SUID/SGID条目在枚举期间变化或超时")
			}
		}
	}
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].Path < s.Entries[j].Path })
	return s, nil
}
func hashPrivilegedInput(ctx context.Context, f *os.File, before unix.Stat_t, path string) (privilegedEntry, int64, error) {
	var opened unix.Stat_t
	if unix.Fstat(int(f.Fd()), &opened) != nil || programFileStamp(opened) != programFileStamp(before) {
		return privilegedEntry{}, 0, fmt.Errorf("SUID/SGID路径在打开期间变化")
	}
	info, err := f.Stat()
	if err != nil {
		return privilegedEntry{}, 0, err
	}
	// ACLs are outside the mode/UID/GID approval contract. Ownership/writability
	// are compared to the reference rather than silently normalized.
	acl, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), "system.posix_acl_access", nil)
	if err != nil && err != unix.ENODATA || acl > 0 {
		return privilegedEntry{}, 0, fmt.Errorf("SUID/SGID选中文件ACL未确认")
	}
	h := sha256.New()
	buffer := make([]byte, 32*1024)
	var total int64
	limited := io.LimitReader(f, before.Size+1)
	for {
		if ctx.Err() != nil {
			return privilegedEntry{}, total, fmt.Errorf("SUID/SGID内容读取超时")
		}
		n, e := limited.Read(buffer)
		total += int64(n)
		if total > before.Size {
			return privilegedEntry{}, total, fmt.Errorf("SUID/SGID内容在读取期间增长")
		}
		h.Write(buffer[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return privilegedEntry{}, total, e
		}
	}
	var after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &after) != nil || programFileStamp(before) != programFileStamp(after) || total != info.Size() {
		return privilegedEntry{}, total, fmt.Errorf("SUID/SGID选中文件在读取期间变化")
	}
	return privilegedEntry{path, fmt.Sprintf("%04o", before.Mode&07777), before.Uid, before.Gid, fmt.Sprintf("%x", h.Sum(nil))}, total, nil
}
func observePrivilegedReference(ctx context.Context, r *pamRead, p programFilesPaths, expected string) (ItemResult, error) {
	raw, err := programReadSmall(ctx, r, p, privilegedReferencePath)
	if err != nil {
		return ItemResult{}, fmt.Errorf("需可信本机审核清单，且不能为链接/硬链接/ACL/不可信输入")
	}
	pinned := privilegedReferenceExpected.FindStringSubmatch(expected)[1]
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	if digest != pinned {
		return ItemResult{}, fmt.Errorf("本机审核清单摘要不等于已审核候选定义")
	}
	reference, err := parsePrivilegedReference(raw, p.arch)
	if err != nil {
		return ItemResult{}, err
	}
	first, err := scanPrivileged(ctx, r, p)
	if err != nil {
		return ItemResult{}, err
	}
	last, err := scanPrivileged(ctx, r, p)
	if err != nil {
		return ItemResult{}, err
	}
	if !reflect.DeepEqual(first, last) {
		return ItemResult{}, fmt.Errorf("SUID/SGID清单、内容或范围元数据在两次查询之间变化")
	}
	bad, sample := comparePrivilegedEntries(reference, first.Entries)
	message := ""
	if bad > 0 {
		message = "限定直接普通文件的当前模式/属主/内容与审核清单不一致"
	}
	return ItemResult{Passed: bad == 0, Actual: fmt.Sprintf("reference_sha256=%s expected_entries=%d observed_entries=%d mismatches=%d observed_sha256=%s excluded_symlinks=%d excluded_directories=%d excluded_other=%d mismatch_sample=[%s]", pinned, len(reference), len(first.Entries), bad, privilegedEntriesDigest(first.Entries), first.ExcludedLinks, first.ExcludedDirectories, first.ExcludedOther, sample), Message: message}, nil
}
