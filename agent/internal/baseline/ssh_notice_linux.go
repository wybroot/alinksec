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
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var sshNoticeVersion = regexp.MustCompile(`^1:9\.6p1-3ubuntu13(\.[0-9]+)?$`)
var sshNoticeKeyword = regexp.MustCompile(`^[A-Za-z]+$`)
var sshNoticeName = regexp.MustCompile(`^[A-Za-z0-9_.?*-]+$`)

type sshNoticePaths struct {
	directory, banner string
	uid, gid          uint32 // production is fixed root:root; isolated fixtures use their owner
}
type sshNoticeQuery func(context.Context, string, *SSHConnection, int) ItemResult
type sshNoticeRead struct {
	r        *pamRead
	paths    sshNoticePaths
	entries  map[string][]string
	visiting map[string]bool
	files    int
	bytes    int64
}

func checkSSHNotice(cs *CheckSpec) ItemResult {
	if !validSSHNotice(cs) {
		return ItemResult{Error: true, Message: "SSH提示定义无效"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${Version}", "openssh-server")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	packageResult := collectBaselineCommand(ctx, cmd, cs.TimeoutMs)
	if packageResult.Error || !sshNoticeVersion.MatchString(packageResult.Actual) {
		return ItemResult{Error: true, Message: "SSH提示需可查询的Ubuntu24 openssh-server 1:9.6p1-3ubuntu13系列"}
	}
	result := sshNoticeWithin(ctx, cs, sshNoticePaths{directory: "/etc/ssh", banner: sshNoticeBanner}, querySSHConfiguration)
	result.Actual = "package_version=" + packageResult.Actual + " " + result.Actual
	return result
}

// Observe finite trusted disk inputs and the parser twice. This is not an
// atomic snapshot or a probe of a listening server or banner delivery.
func sshNoticeWithin(ctx context.Context, cs *CheckSpec, paths sshNoticePaths, query sshNoticeQuery) ItemResult {
	if !validSSHNotice(cs) {
		return ItemResult{Error: true, Message: "SSH提示定义无效"}
	}
	prefix := "scope=ssh-notice-disk-declarations connection=(" + cs.Connection.argument() + ") option=" + cs.Option +
		" loaded_state=unverified command_line_state=unverified banner_delivery_state=unverified name_resolution_state=unverified snapshot_state=non_atomic "
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: message} }
	r := newPAMRead(cs.TimeoutMs)
	if deadline, ok := ctx.Deadline(); ok {
		r.deadline = deadline
	}
	defer r.close()
	n := sshNoticeRead{r: r, paths: paths, entries: map[string][]string{}, visiting: map[string]bool{}}
	for _, dir := range []string{filepath.Dir(paths.directory), paths.directory, filepath.Dir(paths.banner)} {
		if err := n.openDirectory(dir); err != nil {
			return failure("SSH配置或横幅目录不可信、不可读取或超限")
		}
	}
	config := filepath.Join(paths.directory, "sshd_config")
	if err := n.expand(config, 0); err != nil {
		return failure("SSH配置链不满足有限Include语法、可信输入或读取上限")
	}
	first := query(ctx, config, cs.Connection, cs.TimeoutMs)
	if first.Error {
		return failure("SSH原生配置查询失败或超时")
	}
	values, err := sshNoticeOptions(first.Actual)
	if err != nil {
		return failure(err.Error())
	}
	result := ItemResult{Passed: values["usedns"] == "no", Actual: prefix + "usedns=" + values["usedns"]}
	if cs.Option == "banner" {
		result.Passed = false
		switch values["banner"] {
		case "none":
			result.Actual = prefix + "banner=none content_state=not_selected"
		case paths.banner:
			f, err := n.openFile(paths.banner)
			if err != nil {
				return failure("选中的issue.net必须为可信、有界、非链接普通文件")
			}
			data, err := io.ReadAll(io.LimitReader(f, 16*1024+1))
			if err != nil || len(data) > 16*1024 || ctx.Err() != nil {
				return failure("横幅读取失败或超过16KiB/时间上限")
			}
			r.bytes += len(data)
			n.bytes += int64(len(data))
			if n.bytes > 1024*1024 {
				return failure("SSH配置与横幅原始字节总量超过1MiB")
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(data))
			textValid := utf8.Valid(data) && !strings.ContainsFunc(string(data), func(c rune) bool { return unicode.IsControl(c) && c != '\n' && c != '\r' && c != '\t' })
			if !textValid {
				return failure("横幅不是支持的UTF-8文本或含控制字符")
			}
			result.Actual = fmt.Sprintf("%sbanner=%s bytes=%d sha256=%s content_state=digest_checked", prefix, sshNoticeBanner, len(data), digest)
			result.Passed = strings.TrimSpace(string(data)) != "" && cs.Expected == "file="+sshNoticeBanner+",sha256="+digest
		default:
			result.Actual = prefix + "banner=other_path content_state=not_read"
		}
	}
	second := query(ctx, config, cs.Connection, cs.TimeoutMs)
	if second.Error {
		return failure("SSH复核查询失败或超过共同时间上限")
	}
	again, err := sshNoticeOptions(second.Actual)
	if err != nil || again["usedns"] != values["usedns"] || again["banner"] != values["banner"] {
		return failure("SSH配置解析观测在检查期间发生变化")
	}
	if err := r.stable(); err != nil {
		return failure("SSH配置或横幅输入在检查期间发生变化或超限")
	}
	for path, input := range r.inputs {
		if err := n.trusted(path, input); err != nil {
			return failure("SSH输入权限或ACL无法确认")
		}
	}
	result.Actual += fmt.Sprintf(" inputs=%d access_acl=none default_acl=none", len(r.inputs))
	if !result.Passed {
		result.Message = "指定连接的UseDNS名称解析参考或选中issue.net内容摘要未满足明确参考；运行实例和实际提示未验证"
	}
	return result
}

func sshNoticeOptions(output string) (map[string]string, error) {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := fields[0]
		if key != "usedns" && key != "banner" {
			continue
		}
		if len(fields) != 2 || values[key] != "" {
			return nil, fmt.Errorf("SSH提示解析结果缺失、重复或格式无效")
		}
		values[key] = fields[1]
	}
	if values["usedns"] != "yes" && values["usedns"] != "no" || values["banner"] == "" {
		return nil, fmt.Errorf("SSH提示解析结果缺失或值无效")
	}
	return values, nil
}

func (n *sshNoticeRead) trusted(path string, input pamInput) error {
	s := input.info.Sys().(*syscall.Stat_t)
	if s.Uid != n.paths.uid || s.Gid != n.paths.gid || s.Mode&0022 != 0 || input.info.Mode().IsRegular() && s.Nlink != 1 {
		return fmt.Errorf("不可信SSH输入")
	}
	attrs := []string{"system.posix_acl_access"}
	if input.info.IsDir() {
		attrs = append(attrs, "system.posix_acl_default")
	}
	for _, attr := range attrs {
		size, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", input.file.Fd()), attr, nil)
		if err != nil && err != unix.ENODATA || size > 0 {
			return fmt.Errorf("SSH输入ACL未确认")
		}
	}
	return nil
}
func (n *sshNoticeRead) openDirectory(path string) error {
	if _, ok := n.r.inputs[path]; !ok {
		if _, err := n.r.open(path, true); err != nil {
			return err
		}
	}
	return n.trusted(path, n.r.inputs[path])
}
func (n *sshNoticeRead) openFile(path string) (*os.File, error) {
	if input, ok := n.r.inputs[path]; ok {
		return input.file, n.trusted(path, input)
	}
	f, err := n.r.open(path, false)
	if err == nil {
		err = n.trusted(path, n.r.inputs[path])
	}
	return f, err
}
func (n *sshNoticeRead) expand(path string, depth int) error {
	n.files++
	if depth > 8 || n.files > 64 || n.visiting[path] {
		return fmt.Errorf("SSH Include循环或超限")
	}
	n.visiting[path] = true
	defer delete(n.visiting, path)
	_, cached := n.r.content[path]
	lines, err := n.r.lines(path)
	if err != nil {
		return err
	}
	if !cached {
		n.bytes += n.r.inputs[path].info.Size()
	}
	if n.bytes > 1024*1024 {
		return fmt.Errorf("SSH配置原始字节总量超限")
	}
	if err := n.trusted(path, n.r.inputs[path]); err != nil {
		return err
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			if i == 0 || line[i-1] != ' ' && line[i-1] != '\t' {
				return fmt.Errorf("SSH行内注释格式尚未支持")
			}
			line = line[:i]
		}
		// A finite lexical preflight discovers every Include before invoking
		// OpenSSH. Native parsing alone would not bound files or block unsafe
		// named inputs. Quoting/escaping is deliberately unconfirmed.
		if strings.ContainsAny(line, "\"'\\") {
			return fmt.Errorf("SSH引号或转义语法尚未支持")
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !sshNoticeKeyword.MatchString(fields[0]) {
			return fmt.Errorf("SSH关键字语法尚未支持")
		}
		if !strings.EqualFold(fields[0], "Include") {
			continue
		}
		if len(fields) < 2 {
			return fmt.Errorf("SSH Include缺少路径")
		}
		for _, pattern := range fields[1:] {
			for _, part := range strings.Split(pattern, string(os.PathSeparator)) {
				if part == "." || part == ".." {
					return fmt.Errorf("SSH Include相对路径跳转尚未支持")
				}
			}
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(n.paths.directory, pattern)
			}
			if filepath.Clean(pattern) != pattern || !strings.HasPrefix(pattern, n.paths.directory+string(os.PathSeparator)) {
				return fmt.Errorf("SSH Include必须位于固定配置目录")
			}
			dir, base := filepath.Dir(pattern), filepath.Base(pattern)
			if strings.ContainsAny(dir, "*?[") || !sshNoticeName.MatchString(base) {
				return fmt.Errorf("SSH Include仅支持普通目录与末段*或?通配")
			}
			if err := n.includeParents(dir); err != nil {
				return err
			}
			if strings.ContainsAny(base, "*?") {
				names, err := n.directoryEntries(dir)
				if err != nil {
					return err
				}
				for _, name := range names {
					// POSIX glob excludes leading dots unless explicitly present.
					if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
						continue
					}
					matched, err := filepath.Match(base, name)
					if err != nil {
						return err
					}
					if matched {
						if err := n.expand(filepath.Join(dir, name), depth+1); err != nil {
							return err
						}
					}
				}
			} else {
				if _, err := os.Lstat(pattern); os.IsNotExist(err) {
					n.r.absent = append(n.r.absent, pattern)
					continue
				}
				if err := n.expand(pattern, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return n.r.budget()
}
func (n *sshNoticeRead) includeParents(dir string) error {
	rel, err := filepath.Rel(n.paths.directory, dir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("SSH Include目录无效")
	}
	current := n.paths.directory
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if !sshNoticeName.MatchString(part) || strings.ContainsAny(part, "*?") {
			return fmt.Errorf("SSH Include目录尚未支持")
		}
		current = filepath.Join(current, part)
		if err := n.openDirectory(current); err != nil {
			return err
		}
	}
	return nil
}
func (n *sshNoticeRead) directoryEntries(dir string) ([]string, error) {
	if names, ok := n.entries[dir]; ok {
		return names, nil
	}
	f := n.r.inputs[dir].file
	names, err := f.Readdirnames(129)
	if err != nil && err != io.EOF || len(names) > 128 {
		return nil, fmt.Errorf("SSH Include目录枚举失败或超限")
	}
	sort.Strings(names)
	n.entries[dir] = names
	return names, nil
}
