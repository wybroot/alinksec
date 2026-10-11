//go:build linux

package baseline

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Production never calls sudo, visudo or cvtsudoers: even conversion reads
// sudo.conf debug settings. No NSS, PAM, plugin loading or credential checks.
func sudoPackage(ctx context.Context, timeout int) ItemResult {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "--show", "--showformat=${db:Status-Abbrev}\t${Version}\n", "--", "sudo")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	r := collectBaselineCommand(ctx, cmd, timeout)
	if r.Error || r.Actual != "ii \t"+sudoPackageVersion {
		return ItemResult{Error: true, Message: "无法确认完整安装的 sudo " + sudoPackageVersion}
	}
	return r
}

func checkSudoers(cs *CheckSpec) ItemResult { return sudoersWithin(cs, "/", sudoPackage) }

type sudoersPolicy struct {
	authenticate, logAllowed  string // Require explicit values; don't assume compiled defaults.
	exempt, logfile           string
	commands, nopasswd, lines int
	includeSeen               bool
}

var sudoersGrant = regexp.MustCompile(`^(ALL|%?[a-z_][a-z0-9_-]{0,31})[ \t]+ALL[ \t]*=[ \t]*\([ \t]*(ALL|root)[ \t]*(:[ \t]*(ALL|root)[ \t]*)?\)[ \t]*(.+)$`)
var sudoersCommand = regexp.MustCompile(`^(ALL|/[A-Za-z0-9_+./-]+)$`)
var sudoersGroup = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var sudoersIncludeName = regexp.MustCompile(`^[0-9]{2}-[A-Za-z0-9_-]{1,64}$`)
var sudoersDirectoryName = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,128}$`)

func sudoersCleanLine(line string) (string, error) {
	if len(line) > 4096 {
		return "", fmt.Errorf("sudoers 行超过4096字节")
	}
	for _, b := range []byte(line) {
		if b != '\t' && (b < 32 || b > 126) {
			return "", fmt.Errorf("sudoers 需 ASCII/LF 配置")
		}
	}
	// Continuations and quoting escapes can change comment/include boundaries.
	if strings.ContainsRune(line, '\\') {
		return "", fmt.Errorf("sudoers 续行或转义未支持")
	}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#include") || strings.HasPrefix(trimmed, "@include") {
		// The legacy # directive is anchored at column zero in native toke.l.
		if line == "#includedir /etc/sudoers.d" || trimmed == "@includedir /etc/sudoers.d" {
			return "@includedir /etc/sudoers.d", nil
		}
		return "", fmt.Errorf("sudoers 仅支持一次固定 includedir，其他包含形式未支持")
	}
	if strings.HasPrefix(trimmed, "#") {
		if len(trimmed) > 1 && trimmed[1] >= '0' && trimmed[1] <= '9' {
			return "", fmt.Errorf("sudoers 数值 UID 主体未支持")
		}
		return "", nil
	}
	if i := strings.IndexByte(trimmed, '#'); i >= 0 {
		trimmed = strings.TrimSpace(trimmed[:i])
	}
	return trimmed, nil
}

func (p *sudoersPolicy) line(line string) error {
	bad := func() error { return fmt.Errorf("sudoers 超出已支持的全局 Defaults 与简单正授权子集") }
	if line == "" {
		return nil
	}
	if strings.HasPrefix(line, "Defaults ") || strings.HasPrefix(line, "Defaults\t") {
		for _, part := range strings.Split(strings.TrimSpace(line[len("Defaults"):]), ",") {
			part = strings.TrimSpace(part)
			switch part {
			case "authenticate":
				p.authenticate = "on"
			case "!authenticate":
				p.authenticate = "off"
			case "log_allowed":
				p.logAllowed = "on"
			case "!log_allowed":
				p.logAllowed = "off"
			case "!exempt_group":
				p.exempt = ""
			case "!logfile":
				p.logfile = ""
			case "env_reset", "!env_reset", "mail_badpass", "!mail_badpass", "use_pty", "!use_pty", "log_denied", "!log_denied":
				// Supported vendor flags unrelated to these two reference conclusions.
			default:
				pair := strings.Split(part, "=")
				if len(pair) != 2 {
					return bad()
				}
				name, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
				if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) && len(value) >= 2 {
					value = value[1 : len(value)-1]
				}
				if strings.ContainsRune(value, '"') {
					return bad()
				}
				switch name {
				case "exempt_group":
					if !sudoersGroup.MatchString(value) {
						return bad()
					}
					p.exempt = value
				case "logfile":
					if !auditdLogPath(value) {
						return bad()
					}
					p.logfile = value
				case "secure_path":
					if value != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin" && value != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
						return bad()
					}
				default:
					return bad()
				}
			}
		}
		return nil
	}
	match := sudoersGrant.FindStringSubmatch(line)
	if match == nil {
		return bad()
	}
	nopasswd := false
	for _, command := range strings.Split(match[len(match)-1], ",") {
		command = strings.TrimSpace(command)
		if strings.HasPrefix(command, "NOPASSWD:") {
			nopasswd = true
			command = strings.TrimSpace(command[len("NOPASSWD:"):])
		} else if strings.HasPrefix(command, "PASSWD:") {
			nopasswd = false
			command = strings.TrimSpace(command[len("PASSWD:"):])
		}
		if !sudoersCommand.MatchString(command) || command != "ALL" && (filepath.Clean(command) != command || strings.HasSuffix(command, "/")) {
			return bad()
		}
		p.commands++
		if nopasswd {
			p.nopasswd++
		}
	}
	return nil
}

func sudoersNames(f *os.File) ([]string, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("无法枚举 sudoers.d")
	}
	r := os.NewFile(uintptr(fd), "sudoers.d")
	defer r.Close()
	names, err := r.Readdirnames(129)
	if err != nil && err != io.EOF || len(names) > 128 {
		return nil, fmt.Errorf("sudoers.d 无法完整枚举或超过128条目")
	}
	prefixes := map[string]bool{}
	for _, name := range names {
		if !sudoersDirectoryName.MatchString(name) {
			return nil, fmt.Errorf("sudoers.d 文件名未支持")
		}
		// Native skips ANY dot and a trailing tilde. Preserve ignored names in the snapshot.
		if strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue
		}
		if name == "README" {
			continue
		}
		if !sudoersIncludeName.MatchString(name) || prefixes[name[:2]] {
			return nil, fmt.Errorf("sudoers 包含文件需唯一两位数字顺序前缀或厂商README")
		}
		prefixes[name[:2]] = true
	}
	slices.Sort(names)
	return names, nil
}

func sudoersWithin(cs *CheckSpec, root string, probe func(context.Context, int) ItemResult) ItemResult {
	actual := "scope=on-disk-sudoers-declarations authorization_state=unverified authentication_state=unverified delivery_state=unverified"
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: actual, Message: message} }
	if !validSudoers(cs) {
		return failure("sudoers 参考定义无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	if r := probe(ctx, cs.TimeoutMs); r.Error {
		return failure(r.Message)
	}
	actual += " package=sudo version=" + sudoPackageVersion
	var entries []*cronMetadataEntry
	defer func() {
		for _, e := range entries {
			e.f.Close()
		}
	}()
	open := func(target string, directory bool) (*cronMetadataEntry, error) {
		f, parents, err := openLogPath(root, target)
		if err != nil {
			return nil, fmt.Errorf("sudoers 输入缺失、含链接或无法打开：%s", target)
		}
		e := &cronMetadataEntry{f: f, target: target, parents: parents}
		entries = append(entries, e)
		if err := unix.Fstat(int(f.Fd()), &e.stat); err != nil {
			return nil, fmt.Errorf("无法确认 sudoers 元数据")
		}
		kind := uint32(unix.S_IFREG)
		if directory {
			kind = unix.S_IFDIR
		}
		if e.stat.Mode&unix.S_IFMT != kind || !directory && e.stat.Nlink != 1 || e.stat.Uid != 0 || e.stat.Gid != 0 || e.stat.Mode&0022 != 0 {
			return nil, fmt.Errorf("sudoers 输入需UID/GID0、组和其他不可写的普通文件/目录")
		}
		attrs := []string{"system.posix_acl_access"}
		if directory {
			attrs = append(attrs, "system.posix_acl_default")
		}
		for _, attr := range attrs {
			size, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), attr, nil)
			if err != nil && err != unix.ENODATA || size > 0 {
				return nil, fmt.Errorf("sudoers 输入存在ACL或无法确认ACL")
			}
		}
		return e, nil
	}
	p := &sudoersPolicy{authenticate: "unset", logAllowed: "unset"}
	var dir *cronMetadataEntry
	var names []string
	total, files := 0, 0
	var parseFile func(string, bool) error
	parseFile = func(target string, included bool) error {
		if ctx.Err() != nil || files >= 33 {
			return fmt.Errorf("sudoers 超时或超过32个包含文件")
		}
		e, err := open(target, false)
		if err != nil {
			return err
		}
		if e.stat.Size > 64*1024 {
			return fmt.Errorf("sudoers 单文件超过64KiB")
		}
		fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", e.f.Fd()), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("无法读取 sudoers 配置")
		}
		r := os.NewFile(uintptr(fd), target)
		raw, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
		r.Close()
		total += len(raw)
		files++
		if err != nil || len(raw) > 64*1024 || total > 256*1024 || ctx.Err() != nil || len(raw) > 0 && raw[len(raw)-1] != '\n' {
			return fmt.Errorf("sudoers 读取失败、超限、未终止行或超时")
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
			p.lines++
			if p.lines > 4096 {
				return fmt.Errorf("sudoers 超过4096行")
			}
			clean, err := sudoersCleanLine(line)
			if err != nil {
				return err
			}
			if clean == "@includedir /etc/sudoers.d" {
				if included || p.includeSeen {
					return fmt.Errorf("sudoers 嵌套或重复包含未支持")
				}
				p.includeSeen = true
				dir, err = open("/etc/sudoers.d", true)
				if err != nil {
					return err
				}
				names, err = sudoersNames(dir.f)
				if err != nil {
					return err
				}
				for _, name := range names {
					if !strings.Contains(name, ".") && !strings.HasSuffix(name, "~") {
						if err := parseFile("/etc/sudoers.d/"+name, true); err != nil {
							return err
						}
					}
				}
			} else if err := p.line(clean); err != nil {
				return err
			}
		}
		return nil
	}
	if err := parseFile(cs.Target, false); err != nil {
		return failure(err.Error())
	}
	if r := probe(ctx, cs.TimeoutMs); r.Error {
		return failure(r.Message)
	}
	for _, e := range entries {
		now, parents, err := openLogPath(root, e.target)
		if err != nil {
			return failure("sudoers 输入期间被替换")
		}
		var current, held unix.Stat_t
		err = unix.Fstat(int(now.Fd()), &current)
		now.Close()
		heldErr := unix.Fstat(int(e.f.Fd()), &held)
		if err != nil || heldErr != nil || !sameCronStat(e.stat, current) || !sameCronStat(e.stat, held) || e.stat.Size != current.Size || e.stat.Mtim != current.Mtim || len(parents) != len(e.parents) {
			return failure("sudoers 内容或元数据在检查期间变化")
		}
		for i := range parents {
			if !sameLogParent(parents[i], e.parents[i]) {
				return failure("sudoers 父目录在检查期间变化")
			}
		}
	}
	if dir != nil {
		after, err := sudoersNames(dir.f)
		if err != nil || !slices.Equal(names, after) {
			return failure("sudoers 包含集合在检查期间变化")
		}
	}
	if ctx.Err() != nil {
		return failure("sudoers 检查超时")
	}
	// No vacuous pass from an empty policy. A stricter declaration reference may
	// fail even if later matching entries would override a NOPASSWD grant.
	auth := p.authenticate == "on" && p.exempt == "" && p.nopasswd == 0 && p.commands > 0
	logging := p.logAllowed == "on" && p.logfile == "/var/log/sudo.log" && p.commands > 0
	exempt, file := p.exempt, p.logfile
	if exempt == "" {
		exempt = "unset"
	}
	if file == "" {
		file = "unset"
	}
	actual += fmt.Sprintf(" authenticate=%s exempt_group=%s nopasswd_tags=%d log_allowed=%s logfile=%s files=%d commands=%d", p.authenticate, exempt, p.nopasswd, p.logAllowed, file, files, p.commands)
	passed := auth
	if cs.Option == "allowed_logging" {
		passed = logging
	}
	message := ""
	if !passed {
		message = "Sudoers declared policy reference mismatch"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
