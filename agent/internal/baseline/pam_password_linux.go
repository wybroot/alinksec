//go:build linux

package baseline

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type pamPaths struct{ directory, quality, modules string }
type pamInput struct {
	file *os.File
	info os.FileInfo
}
type pamRead struct {
	deadline time.Time
	bytes    int
	inputs   map[string]pamInput
	content  map[string][]string
	stack    []pamRule
	visiting map[string]bool
	absent   []string
}
type pamRule struct {
	control, module string
	args            []string
}

var pamServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var pamInt = regexp.MustCompile(`^-?[0-9]+$`)

func systemPAMPaths() pamPaths {
	arch := ""
	switch runtime.GOARCH {
	case "amd64":
		arch = "x86_64-linux-gnu"
	case "arm64":
		arch = "aarch64-linux-gnu"
	}
	return pamPaths{"/etc/pam.d", "/etc/security/pwquality.conf", filepath.Join("/usr/lib", arch, "security")}
}

func newPAMRead(timeout int) *pamRead {
	return &pamRead{deadline: time.Now().Add(time.Duration(timeout) * time.Millisecond), inputs: map[string]pamInput{}, content: map[string][]string{}, visiting: map[string]bool{}}
}
func (r *pamRead) close() {
	for _, v := range r.inputs {
		v.file.Close()
	}
}
func (r *pamRead) budget() error {
	if time.Now().After(r.deadline) || r.bytes > 1024*1024 || len(r.inputs) > 96 {
		return fmt.Errorf("PAM 输入超过时间、文件数或总读取上限")
	}
	return nil
}
func (r *pamRead) open(path string, directory bool) (*os.File, error) {
	if err := r.budget(); err != nil {
		return nil, err
	}
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("无法读取 PAM 输入 %s", path)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || (!directory && (!info.Mode().IsRegular() || info.Size() > 64*1024)) || (directory && !info.IsDir()) {
		f.Close()
		return nil, fmt.Errorf("PAM 输入必须为有界普通文件或配置目录，且不能为链接")
	}
	r.inputs[path] = pamInput{f, info}
	return f, nil
}
func (r *pamRead) stable() error {
	if err := r.budget(); err != nil {
		return err
	}
	for _, path := range r.absent {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return fmt.Errorf("PAM 缺失输入状态在检查期间发生变化")
		}
	}
	for path, v := range r.inputs {
		a, err := v.file.Stat()
		c, e := os.Lstat(path)
		if err != nil || e != nil || c.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("PAM 输入在检查期间发生变化")
		}
		b, aa, cc := v.info.Sys().(*syscall.Stat_t), a.Sys().(*syscall.Stat_t), c.Sys().(*syscall.Stat_t)
		if b.Dev != aa.Dev || b.Ino != aa.Ino || aa.Dev != cc.Dev || aa.Ino != cc.Ino || b.Size != aa.Size || b.Mtim != aa.Mtim || b.Ctim != aa.Ctim || aa.Ctim != cc.Ctim {
			return fmt.Errorf("PAM 输入在检查期间发生变化")
		}
	}
	return nil
}
func (r *pamRead) lines(path string) ([]string, error) {
	if lines, ok := r.content[path]; ok {
		return lines, nil
	}
	f, err := r.open(path, false)
	if err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: f, N: 64*1024 + 1}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 1024), 16*1024)
	var lines []string
	for scan.Scan() {
		line := scan.Text()
		r.bytes += len(line) + 1
		if !utf8.ValidString(line) || strings.ContainsFunc(line, func(c rune) bool { return c < 32 && c != '\t' && c != '\r' || c == 127 }) || len(lines) >= 1024 {
			return nil, fmt.Errorf("PAM 输入格式或行数无效")
		}
		if err := r.budget(); err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	if scan.Err() != nil || limited.N == 0 {
		return nil, fmt.Errorf("PAM 输入读取失败或超过行长度上限")
	}
	r.content[path] = lines
	return lines, nil
}

// Expand only the selected management group; other groups are outside this check.
// Includes remain inside this directory; fallback/vendor trees and substacks are
// deliberately unconfirmed rather than guessed.
func (r *pamRead) expand(directory, name string, depth int) error {
	return r.expandGroup(directory, name, "password", depth)
}

func (r *pamRead) expandGroup(directory, name, group string, depth int) error {
	if !pamServiceName.MatchString(name) || depth > 8 || r.visiting[name] {
		return fmt.Errorf("PAM include 名称、深度或循环无效")
	}
	r.visiting[name] = true
	defer delete(r.visiting, name)
	lines, err := r.lines(filepath.Join(directory, name))
	if err != nil {
		return err
	}
	pending := ""
	for _, physical := range lines {
		physical = strings.TrimSuffix(physical, "\r")
		if strings.HasSuffix(physical, "\\") {
			pending += strings.TrimSuffix(physical, "\\")
			if len(pending) > 16*1024 {
				return fmt.Errorf("PAM 续行超限")
			}
			continue
		}
		line := pending + physical
		pending = ""
		if at := strings.IndexByte(line, '#'); at >= 0 {
			line = line[:at]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		first := strings.Fields(line)
		if first[0] == "@include" {
			if len(first) != 2 {
				return fmt.Errorf("PAM include 格式无效")
			}
			if err := r.expandGroup(directory, first[1], group, depth+1); err != nil {
				return err
			}
			continue
		}
		kind := strings.ToLower(first[0])
		if kind != group {
			if kind != "auth" && kind != "password" && kind != "account" && kind != "session" {
				return fmt.Errorf("PAM 管理组尚未支持")
			}
			continue
		}
		rest := strings.TrimSpace(line[len(first[0]):])
		control := ""
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return fmt.Errorf("PAM 控制字段无效")
			}
			pairs := strings.Fields(rest[1:end])
			sort.Strings(pairs)
			control = "[" + strings.Join(pairs, " ") + "]"
			rest = strings.TrimSpace(rest[end+1:])
		} else {
			parts := strings.Fields(rest)
			if len(parts) < 2 {
				return fmt.Errorf("PAM 管理组行无效")
			}
			control = strings.ToLower(parts[0])
			rest = strings.TrimSpace(rest[len(parts[0]):])
		}
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			return fmt.Errorf("PAM 模块字段缺失")
		}
		if control == "include" {
			if len(parts) != 1 {
				return fmt.Errorf("PAM include 格式无效")
			}
			if err := r.expandGroup(directory, parts[0], group, depth+1); err != nil {
				return err
			}
			continue
		}
		if control == "substack" || strings.ContainsAny(rest, "[]\\\"") {
			return fmt.Errorf("PAM 子栈或参数语法尚未支持")
		}
		r.stack = append(r.stack, pamRule{control, parts[0], parts[1:]})
		if len(r.stack) > 64 {
			return fmt.Errorf("PAM 展开项超限")
		}
	}
	if pending != "" {
		return fmt.Errorf("PAM 续行不完整")
	}
	return r.budget()
}

func pamModuleName(value, dir string) (string, error) {
	name := filepath.Base(value)
	if value != name && value != filepath.Join(dir, name) && value != strings.Replace(filepath.Join(dir, name), "/usr/lib/", "/lib/", 1) {
		return "", fmt.Errorf("PAM 模块路径尚未支持")
	}
	switch name {
	case "pam_pwquality.so", "pam_unix.so", "pam_deny.so", "pam_permit.so":
		return name, nil
	}
	return "", fmt.Errorf("PAM 模块或额外身份源尚未支持")
}
func pamTopology(stack []pamRule, dir string) (*pamRule, *pamRule, error) {
	for i := range stack {
		name, err := pamModuleName(stack[i].module, dir)
		if err != nil {
			return nil, nil, err
		}
		stack[i].module = name
	}
	var quality *pamRule
	if len(stack) > 0 && stack[0].module == "pam_pwquality.so" {
		quality = &stack[0]
		if quality.control != "requisite" {
			return nil, nil, fmt.Errorf("质量模块需要已支持的 requisite 控制；其他流程无法确认")
		}
		stack = stack[1:]
	}
	if len(stack) != 3 || stack[0].module != "pam_unix.so" || stack[0].control != "[default=ignore success=1]" || stack[1].module != "pam_deny.so" || stack[1].control != "requisite" || len(stack[1].args) != 0 || stack[2].module != "pam_permit.so" || stack[2].control != "required" || len(stack[2].args) != 0 {
		return nil, nil, fmt.Errorf("PAM password 链不符合已支持的本地 unix、deny、permit 顺序及控制")
	}
	return quality, &stack[0], nil
}
func pamUnixArgs(args []string) (string, bool, error) {
	seen := map[string]bool{}
	algorithm := "unspecified"
	bound := false
	for _, arg := range args {
		if seen[arg] {
			return "", false, fmt.Errorf("pam_unix 参数重复")
		}
		seen[arg] = true
		switch arg {
		case "yescrypt", "sha512", "sha256", "md5", "bigcrypt", "blowfish", "des":
			if algorithm != "unspecified" {
				return "", false, fmt.Errorf("pam_unix 散列算法冲突")
			}
			algorithm = arg
		case "use_authtok":
			bound = true
		case "obscure", "try_first_pass", "use_first_pass", "shadow", "nullok":
		default:
			return "", false, fmt.Errorf("pam_unix 参数尚未支持")
		}
	}
	return algorithm, bound, nil
}

func pamQualitySettings(r *pamRead, paths pamPaths, args []string) (map[string]int, error) {
	// libpwquality 1.4.5 defaults, the Ubuntu24.04 product validated natively.
	settings := map[string]int{"minlen": 8, "minclass": 0, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "enforcing": 1, "enforce_for_root": 0, "local_users_only": 0}
	numeric := map[string]bool{}
	for _, key := range []string{"minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit", "enforcing", "difok", "maxrepeat", "maxclassrepeat", "maxsequence", "gecoscheck", "dictcheck", "usercheck", "usersubstr", "retry"} {
		numeric[key] = true
	}
	apply := func(key, value string) error {
		key = strings.ToLower(key)
		if key == "enforce_for_root" || key == "local_users_only" {
			settings[key] = 1
			return nil
		} // SET flags ignore supplied values in 1.4.5.
		if key == "badwords" || key == "dictpath" {
			return nil
		} // Neither changes the length/class reference; never echo strings.
		if !numeric[key] || !pamInt.MatchString(value) {
			return fmt.Errorf("pwquality 配置项或整数无效")
		}
		n, err := strconv.ParseInt(value, 10, 32)
		if err != nil || n <= -2147483648 || n >= 2147483647 {
			return fmt.Errorf("pwquality 整数超限")
		}
		if key == "minlen" && n < 6 {
			n = 6
		}
		if key == "minclass" && n > 4 {
			n = 4
		}
		settings[key] = int(n)
		return nil
	}
	parse := func(path string) error {
		lines, err := r.lines(path)
		if err != nil {
			return err
		}
		for _, line := range lines {
			if len(line) >= 1023 {
				return fmt.Errorf("pwquality 行超过原生解析长度")
			}
			if at := strings.IndexByte(line, '#'); at >= 0 {
				line = line[:at]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			at := strings.IndexAny(line, "= \t\r")
			key, value := line, ""
			if at >= 0 {
				key = line[:at]
				value = strings.TrimSpace(line[at:])
				value = strings.TrimSpace(strings.TrimPrefix(value, "="))
			}
			if err := apply(key, value); err != nil {
				return err
			}
		}
		return nil
	}
	// Require the main config, despite upstream's missing-default-file fallback.
	// Optional missing drop-in directory is recorded explicitly in evidence.
	dir := paths.quality + ".d"
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("pwquality drop-in 必须为非链接目录")
		}
		f, err := r.open(dir, true)
		if err != nil {
			return nil, err
		}
		entries, err := f.ReadDir(129)
		if err != nil && err != io.EOF || len(entries) > 128 {
			return nil, fmt.Errorf("pwquality drop-in 枚举失败或超限")
		}
		var names []string
		for _, entry := range entries {
			if at := strings.Index(entry.Name(), ".conf"); at >= 0 && at == len(entry.Name())-5 {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		if len(names) > 64 {
			return nil, fmt.Errorf("pwquality drop-in 文件数超限")
		}
		for _, name := range names {
			if err := parse(filepath.Join(dir, name)); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("pwquality drop-in 状态无法确认")
	} else {
		r.absent = append(r.absent, dir)
	}
	if err := parse(paths.quality); err != nil {
		return nil, err
	}
	for _, arg := range args {
		if arg == "debug" || arg == "use_authtok" || arg == "use_first_pass" || arg == "try_first_pass" {
			continue
		}
		key, value, has := strings.Cut(arg, "=")
		if !has && key != "enforce_for_root" && key != "local_users_only" {
			return nil, fmt.Errorf("pwquality 模块参数无效")
		}
		if err := apply(key, value); err != nil {
			return nil, err
		}
	}
	if settings["local_users_only"] != 0 {
		return nil, fmt.Errorf("local_users_only 的额外身份分支尚未确认")
	}
	return settings, nil
}

func checkPAMPassword(cs *CheckSpec) ItemResult { return pamPasswordWithin(cs, systemPAMPaths()) }
func pamPasswordWithin(cs *CheckSpec, paths pamPaths) ItemResult {
	r := newPAMRead(cs.TimeoutMs)
	defer r.close()
	prefix := "scope=passwd-password-chain service=/etc/pam.d/passwd "
	failure := func(err error) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: err.Error()} }
	if _, err := r.open(paths.directory, true); err != nil {
		return failure(err)
	}
	if err := r.expand(paths.directory, "passwd", 0); err != nil {
		return failure(err)
	}
	quality, writer, err := pamTopology(r.stack, paths.modules)
	if err != nil {
		return failure(err)
	}
	for _, rule := range r.stack {
		info, err := os.Stat(filepath.Join(paths.modules, rule.module))
		if err != nil || !info.Mode().IsRegular() {
			return failure(fmt.Errorf("PAM 所需模块文件缺失或非普通文件"))
		}
	}
	algorithm, bound, err := pamUnixArgs(writer.args)
	if err != nil {
		return failure(err)
	}
	actual := fmt.Sprintf("%sstack=local-unix-deny-permit quality_present=%t unix_use_authtok=%t algorithm=%s", prefix, quality != nil, bound, algorithm)
	var settings map[string]int
	if quality != nil {
		settings, err = pamQualitySettings(r, paths, quality.args)
		if err != nil {
			return failure(err)
		}
	}
	if err := r.stable(); err != nil {
		return failure(err)
	}
	actual += fmt.Sprintf(" inputs=%d", len(r.inputs))
	if cs.Option == "unix_hash" {
		if algorithm == "unspecified" {
			return failure(fmt.Errorf("pam_unix 未明确选择散列算法，编译默认值无法确认"))
		}
		result := ItemResult{Passed: algorithm == "yescrypt", Actual: actual + " expected=yescrypt"}
		if !result.Passed {
			result.Message = "passwd 服务的 pam_unix 新口令散列选择不满足 yescrypt 参考"
		}
		return result
	}
	if quality == nil {
		return ItemResult{Actual: actual, Message: "已支持的 passwd password 链未包含强制 pam_pwquality 质量模块"}
	}
	actual += fmt.Sprintf(" minlen=%d minclass=%d dcredit=%d ucredit=%d lcredit=%d ocredit=%d enforcing=%d enforce_for_root=%d", settings["minlen"], settings["minclass"], settings["dcredit"], settings["ucredit"], settings["lcredit"], settings["ocredit"], settings["enforcing"], settings["enforce_for_root"])
	passed := bound && settings["minlen"] >= 12 && settings["minclass"] >= 3 && settings["dcredit"] <= 0 && settings["ucredit"] <= 0 && settings["lcredit"] <= 0 && settings["ocredit"] <= 0 && settings["enforcing"] == 1 && settings["enforce_for_root"] == 1
	result := ItemResult{Passed: passed, Actual: actual}
	if !passed {
		result.Message = "质量长度、字符类别、credit、强制执行或口令传递不满足明确参考"
	}
	return result
}
