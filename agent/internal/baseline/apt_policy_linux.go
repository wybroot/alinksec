//go:build linux

package baseline

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func aptPackage(ctx context.Context, timeout int) ItemResult {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "--show", "--showformat=${db:Status-Abbrev}\t${Package}\t${Version}\n", "--", "apt", "libapt-pkg6.0t64")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	r := collectBaselineCommand(ctx, cmd, timeout)
	if r.Error || r.Actual != "ii \tapt\t"+aptPackageVersion+"\nii \tlibapt-pkg6.0t64\t"+aptPackageVersion {
		return ItemResult{Error: true, Message: "无法确认完整安装的 apt/libapt-pkg6.0t64 " + aptPackageVersion}
	}
	return r
}
func checkAPTPolicy(cs *CheckSpec) ItemResult  { return aptPolicyWithin(cs, "/", aptPackage) }
func checkAPTSources(cs *CheckSpec) ItemResult { return aptPolicyWithin(cs, "/", aptPackage) }

func aptPartSelected(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || !aptPartName.MatchString(name) {
		return false
	}
	i := strings.LastIndexByte(name, '.')
	return i < 0 || name[i+1:] == "conf"
}
func aptNames(f *os.File) ([]string, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("无法枚举 APT 配置目录")
	}
	r := os.NewFile(uintptr(fd), "apt-directory")
	defer r.Close()
	names, err := r.Readdirnames(129)
	if err != nil && err != io.EOF || len(names) > 128 {
		return nil, fmt.Errorf("APT 配置目录无法完整枚举或超过128条目")
	}
	for _, name := range names {
		if len(name) > 255 {
			return nil, fmt.Errorf("APT 配置文件名超限")
		}
		for _, c := range []byte(name) {
			if c < 32 || c > 126 {
				return nil, fmt.Errorf("APT 配置文件名需 ASCII")
			}
		}
	}
	slices.Sort(names)
	return names, nil
}

func aptPolicyWithin(cs *CheckSpec, root string, probe func(context.Context, int) ItemResult) ItemResult {
	actual := "scope=default-on-disk-apt-install-policy environment_state=unverified command_line_state=unverified source_trust_state=unverified installation_state=unverified"
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: actual, Message: message} }
	sourceMode := validAPTSources(cs)
	if sourceMode {
		actual = "scope=default-on-disk-apt-source-declarations environment_state=unverified command_line_state=unverified key_identity_state=unverified key_material_state=unverified repository_signature_state=unverified cached_release_state=unverified installation_state=unverified"
	}
	if !validAPTPolicy(cs) && !sourceMode {
		return failure("APT 安装策略参考无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	if r := probe(ctx, cs.TimeoutMs); r.Error {
		return failure(r.Message)
	}
	actual += " package=apt/libapt-pkg6.0t64 version=" + aptPackageVersion
	var entries []*cronMetadataEntry
	defer func() {
		for _, e := range entries {
			e.f.Close()
		}
	}()
	open := func(target string, directory bool) (*cronMetadataEntry, error) {
		f, parents, err := openLogPath(root, target)
		if err != nil {
			return nil, fmt.Errorf("APT 输入缺失、含链接或无法打开：%s", target)
		}
		e := &cronMetadataEntry{f: f, target: target, parents: parents}
		entries = append(entries, e)
		if err := unix.Fstat(int(f.Fd()), &e.stat); err != nil {
			return nil, fmt.Errorf("无法确认 APT 输入元数据")
		}
		kind := uint32(unix.S_IFREG)
		if directory {
			kind = unix.S_IFDIR
		}
		if e.stat.Mode&unix.S_IFMT != kind || !directory && e.stat.Nlink != 1 || e.stat.Uid != 0 || e.stat.Gid != 0 || e.stat.Mode&0022 != 0 {
			return nil, fmt.Errorf("APT 输入需UID/GID0、组和其他不可写的普通文件/目录")
		}
		attrs := []string{"system.posix_acl_access"}
		if directory {
			attrs = append(attrs, "system.posix_acl_default")
		}
		for _, attr := range attrs {
			size, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), attr, nil)
			if err != nil && err != unix.ENODATA || size > 0 {
				return nil, fmt.Errorf("APT 输入存在ACL或无法确认ACL")
			}
		}
		return e, nil
	}
	parent, err := open("/etc/apt", true)
	if err != nil {
		return failure(err.Error())
	}
	parentNames, err := aptNames(parent.f)
	if err != nil {
		return failure(err.Error())
	}
	parts, err := open("/etc/apt/apt.conf.d", true)
	if err != nil {
		return failure(err.Error())
	}
	partNames, err := aptNames(parts.f)
	if err != nil {
		return failure(err.Error())
	}
	selected := 0
	for _, name := range partNames {
		if aptPartSelected(name) {
			selected++
		}
	}
	if selected > 32 {
		return failure("APT 超过32个配置片段")
	}
	tree := aptTree{}
	files, total, lines := 0, 0, 0
	readFile := func(target string) ([]byte, error) {
		if ctx.Err() != nil || files >= 66 {
			return nil, fmt.Errorf("APT 检查超时或超过32个配置片段")
		}
		e, err := open(target, false)
		if err != nil {
			return nil, err
		}
		if e.stat.Size > 64*1024 {
			return nil, fmt.Errorf("APT 单文件超过64KiB")
		}
		fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", e.f.Fd()), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("无法读取 APT 配置")
		}
		r := os.NewFile(uintptr(fd), target)
		raw, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
		r.Close()
		files++
		total += len(raw)
		lines += strings.Count(string(raw), "\n")
		if err != nil || len(raw) > 64*1024 || total > 256*1024 || lines > 4096 || ctx.Err() != nil || len(raw) > 0 && raw[len(raw)-1] != '\n' {
			return nil, fmt.Errorf("APT 配置读取失败、超限、未终止行或超时")
		}
		return raw, nil
	}
	parseFile := func(target string) error {
		raw, err := readFile(target)
		if err != nil {
			return err
		}
		return tree.parseMode(string(raw), sourceMode)
	}
	for _, name := range partNames {
		if aptPartSelected(name) {
			if err := parseFile("/etc/apt/apt.conf.d/" + name); err != nil {
				return failure(err.Error())
			}
		}
	}
	mainPresent := slices.Contains(parentNames, "apt.conf")
	if mainPresent {
		if err := parseFile("/etc/apt/apt.conf"); err != nil {
			return failure(err.Error())
		}
	}
	directorySnapshots := []struct {
		e     *cronMetadataEntry
		names []string
	}{{parent, parentNames}, {parts, partNames}}
	sourceResult := ItemResult{}
	if sourceMode {
		// Source-loading redirects and additional volatile source entries require
		// another contract; Binary overlays must not silently change our scope.
		for key := range tree {
			k := aptContextKey(key)
			for _, banned := range []string{"dir::etc::sourcelist", "dir::etc::sourceparts", "apt::sources::with"} {
				if k == banned || strings.HasPrefix(k, banned+"::") {
					return failure("APT 软件源加载重定向/额外源未支持")
				}
			}
			for _, boolean := range aptSourceBoolKeys {
				if strings.HasPrefix(k, boolean+"::") {
					return failure("APT 软件源布尔项不能含列表/子项")
				}
			}
		}
		sourcesDir, err := open("/etc/apt/sources.list.d", true)
		if err != nil {
			return failure(err.Error())
		}
		sourceNames, err := aptNames(sourcesDir.f)
		if err != nil {
			return failure(err.Error())
		}
		directorySnapshots = append(directorySnapshots, struct {
			e     *cronMetadataEntry
			names []string
		}{sourcesDir, sourceNames})
		selected := 0
		for _, name := range sourceNames {
			if aptSourceSelected(name) {
				selected++
			}
		}
		if selected > 32 {
			return failure("APT 超过32个软件源片段")
		}
		sources := aptSources{}
		loadSource := func(target string) error {
			raw, err := readFile(target)
			if err != nil {
				return err
			}
			return sources.parse(string(raw), strings.HasSuffix(target, ".sources"))
		}
		if slices.Contains(parentNames, "sources.list") {
			if err := loadSource("/etc/apt/sources.list"); err != nil {
				return failure(err.Error())
			}
		}
		for _, name := range sourceNames {
			if aptSourceSelected(name) {
				if err := loadSource("/etc/apt/sources.list.d/" + name); err != nil {
					return failure(err.Error())
				}
			}
		}
		keyDirs := map[string]bool{}
		sourceResult = evaluateAPTSources(tree, &sources, func(target string) error {
			dir := path.Dir(target)
			if !keyDirs[dir] {
				if _, err := open(dir, true); err != nil {
					return err
				}
				keyDirs[dir] = true
			}
			e, err := open(target, false)
			if err != nil {
				return err
			}
			if e.stat.Size < 1 || e.stat.Size > 1024*1024 || e.stat.Mode&0444 != 0444 {
				return fmt.Errorf("APT keyring需非空、最多1MiB且所有用户可读；不验证密钥内容")
			}
			return nil
		})
		if sourceResult.Error {
			return failure(sourceResult.Message)
		}
	}

	if r := probe(ctx, cs.TimeoutMs); r.Error {
		return failure(r.Message)
	}
	for _, e := range entries {
		now, parents, err := openLogPath(root, e.target)
		if err != nil {
			return failure("APT 输入期间被替换")
		}
		var current, held unix.Stat_t
		err = unix.Fstat(int(now.Fd()), &current)
		now.Close()
		heldErr := unix.Fstat(int(e.f.Fd()), &held)
		if err != nil || heldErr != nil || !sameCronStat(e.stat, current) || !sameCronStat(e.stat, held) || e.stat.Size != current.Size || e.stat.Size != held.Size || e.stat.Mtim != current.Mtim || e.stat.Mtim != held.Mtim || len(parents) != len(e.parents) {
			return failure("APT 内容或元数据在检查期间变化")
		}
		for i := range parents {
			if !sameLogParent(parents[i], e.parents[i]) {
				return failure("APT 父目录在检查期间变化")
			}
		}
	}
	for _, pair := range directorySnapshots {
		after, err := aptNames(pair.e.f)
		if err != nil || !slices.Equal(after, pair.names) {
			return failure("APT 配置名称集合在检查期间变化")
		}
	}
	if sourceMode {
		if ctx.Err() != nil {
			return failure("APT 检查超时")
		}
		sourceResult.Actual = actual + " " + sourceResult.Actual + fmt.Sprintf(" files=%d", files)
		return sourceResult
	}

	passed := true
	for _, binary := range []string{"apt", "apt-get"} {
		for _, key := range aptBoolKeys {
			value, origin, err := tree.resolved(binary, key)
			if err != nil {
				return failure(err.Error())
			}
			actual += fmt.Sprintf(" %s.%s=%t(%s)", binary, strings.TrimPrefix(key, "apt::get::"), value, origin)
			passed = passed && !value
		}
	}
	if ctx.Err() != nil {
		return failure("APT 检查超时")
	}
	actual += fmt.Sprintf(" main_present=%t files=%d", mainPresent, files)
	r := ItemResult{Passed: passed, Actual: actual}
	if !passed {
		r.Message = "APT 默认磁盘安装策略允许未认证安装或 Force-Yes，未满足参考"
	}
	return r
}
