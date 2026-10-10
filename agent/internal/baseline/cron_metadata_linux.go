//go:build linux

package baseline

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func cronPackage(ctx context.Context, timeout int) ItemResult {
	// Fixed database and clean environment; no shell, DPKG_ROOT, candidate
	// package/executable selectors, NSS or service operations.
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "--show", "--showformat=${db:Status-Abbrev}\t${Version}\n", "--", "cron")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	result := collectBaselineCommand(ctx, cmd, timeout)
	if result.Error || result.Actual != "ii \t"+cronPackageVersion {
		return ItemResult{Error: true, Message: "无法确认已支持且完整安装的 cron 3.0pl1-184ubuntu2 软件包"}
	}
	return result
}

func checkCronMetadata(cs *CheckSpec) ItemResult { return cronMetadataWithin(cs, "/", cronPackage) }

type cronMetadataEntry struct {
	f       *os.File
	target  string
	stat    unix.Stat_t
	parents []unix.Stat_t
}

func sameCronStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid &&
		a.Gid == b.Gid && a.Nlink == b.Nlink && a.Ctim == b.Ctim &&
		(a.Mode&unix.S_IFMT != unix.S_IFDIR || a.Mtim == b.Mtim)
}

var cronMetadataName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func cronDirectoryNames(f *os.File) ([]string, error) {
	// Read the held directory, at most 129 names (128 supported).
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("无法枚举 cron.d 目录")
	}
	r := os.NewFile(uintptr(fd), "cron.d")
	defer r.Close()
	names, err := r.Readdirnames(129)
	if err != nil && err != io.EOF || len(names) > 128 {
		return nil, fmt.Errorf("cron.d 无法完整枚举或超过 128 条目上限")
	}
	for _, name := range names {
		if !cronMetadataName.MatchString(name) || name == "." || name == ".." {
			return nil, fmt.Errorf("cron.d 含未支持的文件名")
		}
	}
	slices.Sort(names)
	return names, nil
}

// Private roots/probes are test seams. Production always checks real fixed
// paths and the real package. No task contents are read, parsed or executed.
func cronMetadataWithin(cs *CheckSpec, root string, probe func(context.Context, int) ItemResult) ItemResult {
	prefix := "scope=on-disk-debian-cron-system-tables loaded_state=unverified"
	fail := func(message string) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: message} }
	if !validCronMetadata(cs) {
		return fail("cron 系统任务元数据参考定义无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	if result := probe(ctx, cs.TimeoutMs); result.Error {
		return fail(result.Message)
	}
	prefix += " package=cron version=" + cronPackageVersion
	var entries []*cronMetadataEntry
	defer func() {
		for _, entry := range entries {
			entry.f.Close()
		}
	}()
	open := func(target string, directory bool) (*cronMetadataEntry, error) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("cron 元数据检查超时")
		}
		f, parents, err := openLogPath(root, target)
		if err != nil {
			return nil, fmt.Errorf("cron 路径缺失、含链接或无法打开：%s", target)
		}
		entry := &cronMetadataEntry{f: f, target: target, parents: parents}
		entries = append(entries, entry)
		if err := unix.Fstat(int(f.Fd()), &entry.stat); err != nil {
			return nil, fmt.Errorf("无法读取 cron 元数据：%s", target)
		}
		kind := uint32(unix.S_IFREG)
		if directory {
			kind = unix.S_IFDIR
		}
		if entry.stat.Mode&unix.S_IFMT != kind || !directory && entry.stat.Nlink != 1 {
			return nil, fmt.Errorf("cron 目标不是预期普通文件/目录，或存在链接：%s", target)
		}
		attributes := []string{"system.posix_acl_access"}
		if directory {
			attributes = append(attributes, "system.posix_acl_default")
		}
		for _, attribute := range attributes {
			size, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), attribute, nil)
			if err != nil && err != unix.ENODATA || size > 0 {
				return nil, fmt.Errorf("cron 存在 ACL 或无法确认 ACL：%s", target)
			}
		}
		return entry, nil
	}
	tab, err := open("/etc/crontab", false)
	if err != nil {
		return fail(err.Error())
	}
	dir, err := open("/etc/cron.d", true)
	if err != nil {
		return fail(err.Error())
	}
	names, err := cronDirectoryNames(dir.f)
	if err != nil {
		return fail(err.Error())
	}
	for _, name := range names {
		if _, err := open("/etc/cron.d/"+name, false); err != nil {
			return fail(err.Error())
		}
	}
	if result := probe(ctx, cs.TimeoutMs); result.Error {
		return fail("cron 软件包状态在检查期间无法再次确认")
	}
	afterNames, err := cronDirectoryNames(dir.f)
	if err != nil || !slices.Equal(names, afterNames) {
		return fail("cron.d 条目在检查期间发生变化，请重试")
	}
	violations := 0
	var examples []string
	for _, entry := range entries {
		var after unix.Stat_t
		current, parents, err := openLogPath(root, entry.target)
		if err != nil {
			return fail("cron 路径在检查期间发生变化，请重试")
		}
		var currentStat unix.Stat_t
		currentErr := unix.Fstat(int(current.Fd()), &currentStat)
		current.Close()
		stable := unix.Fstat(int(entry.f.Fd()), &after) == nil && currentErr == nil &&
			sameCronStat(entry.stat, after) && sameCronStat(entry.stat, currentStat) && len(parents) == len(entry.parents)
		if stable {
			for i := range parents {
				stable = stable && sameCronStat(parents[i], entry.parents[i])
			}
		}
		if !stable || ctx.Err() != nil {
			return fail("cron 路径/元数据在检查期间发生变化或检查超时，请重试")
		}
		allowed := uint32(0644)
		if entry == dir {
			allowed = 0755
		}
		if entry.stat.Mode&07777 & ^allowed != 0 || entry.stat.Uid != 0 || entry.stat.Gid != 0 {
			violations++
			if len(examples) < 4 {
				examples = append(examples, fmt.Sprintf("%s:mode=%04o,uid=%d,gid=%d", entry.target, entry.stat.Mode&07777, entry.stat.Uid, entry.stat.Gid))
			}
		}
	}
	prefix += fmt.Sprintf(" crontab_mode=%04o cron.d_mode=%04o entries=%d checked=%d violations=%d access_acl=none default_acl=none reference=%s",
		tab.stat.Mode&07777, dir.stat.Mode&07777, len(names), len(entries), violations, cronMetadataReference)
	if len(examples) > 0 {
		prefix += " examples=" + strings.Join(examples, ";")
	}
	result := ItemResult{Passed: violations == 0, Actual: prefix}
	if !result.Passed {
		result.Message = "已完整观察的 cron 系统任务路径权限或数值 UID/GID 不满足参考"
	}
	return result
}
