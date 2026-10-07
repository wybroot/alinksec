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

// No native config evaluation, daemon start, log read or action execution in
// production. The package probe is fixed; it does not establish binary trust.
func rsyslogPackage(ctx context.Context, timeout int) ItemResult {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "--show", "--showformat=${db:Status-Abbrev}\t${Version}\n", "--", "rsyslog")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	r := collectBaselineCommand(ctx, cmd, timeout)
	if r.Error || r.Actual != "ii \t"+rsyslogPackageVersion {
		return ItemResult{Error: true, Message: "无法确认完整安装的 rsyslog " + rsyslogPackageVersion}
	}
	return r
}

func checkRsyslogCron(cs *CheckSpec) ItemResult { return rsyslogCronWithin(cs, "/", rsyslogPackage) }

var rsyslogFacilities = map[string]bool{
	"*": true, "auth": true, "authpriv": true, "cron": true, "daemon": true,
	"kern": true, "lpr": true, "mail": true, "mark": true, "news": true,
	"ntp": true, "security": true, "bsd_security": true, "syslog": true,
	"user": true, "uucp": true, "ftp": true, "console": true,
	"local0": true, "local1": true, "local2": true, "local3": true, "local4": true,
	"local5": true, "local6": true, "local7": true,
}
var rsyslogSeverities = map[string]int{
	"emerg": 0, "panic": 0, "alert": 1, "crit": 2, "err": 3, "error": 3,
	"warning": 4, "warn": 4, "notice": 5, "info": 6, "debug": 7,
}

// DecodePRIFilter in the exact supported source: positive clauses ADD bits,
// negated clauses REMOVE bits, none resets and * assigns all. Do not replace
// this with a last-selector-wins approximation of the documentation.
func rsyslogCronSelector(selector string) (uint8, error) {
	var mask uint8
	for _, clause := range strings.Split(selector, ";") {
		parts := strings.Split(clause, ".")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return 0, fmt.Errorf("rsyslog 选择器未支持")
		}
		applies := false
		for _, facility := range strings.Split(parts[0], ",") {
			if !rsyslogFacilities[facility] {
				return 0, fmt.Errorf("rsyslog facility 未支持")
			}
			applies = applies || facility == "cron" || facility == "*"
		}
		priority := parts[1]
		negate := strings.HasPrefix(priority, "!")
		if negate {
			priority = priority[1:]
		}
		exact := strings.HasPrefix(priority, "=")
		if exact {
			priority = priority[1:]
		}
		var bits uint8
		reset := priority == "none" || priority == "*"
		if reset {
			if exact {
				return 0, fmt.Errorf("rsyslog 精确特殊级别未支持")
			}
			if priority == "*" {
				bits = 255
			}
		} else {
			p, ok := rsyslogSeverities[priority]
			if !ok {
				return 0, fmt.Errorf("rsyslog severity 未支持")
			}
			bits = uint8(1 << p)
			if !exact {
				bits = uint8(1<<(p+1) - 1)
			}
		}
		if applies {
			if reset {
				mask = bits
				if negate {
					mask = ^bits
				}
			} else if negate {
				mask &^= bits
			} else {
				mask |= bits
			}
		}
	}
	return mask, nil
}

type rsyslogRouting struct {
	active, covered, last                        uint8
	previousRule, input, moduleSeen, includeSeen bool
	seen                                         map[string]bool
	rules, lines                                 int
}

// Only these vendor globals, with these exact values, are in scope. No
// templates, queues, rulesets, dynamic files, plugins, custom inputs or shells.
var rsyslogGlobals = map[string]string{
	"$RepeatedMsgReduction": "on|off", "$FileOwner": "syslog", "$FileGroup": "adm",
	"$FileCreateMode": "0640", "$DirCreateMode": "0755", "$Umask": "0022",
	"$PrivDropToUser": "syslog", "$PrivDropToGroup": "syslog",
	"$WorkDirectory":             "/var/spool/rsyslog",
	"$ActionFileDefaultTemplate": "RSYSLOG_TraditionalFileFormat|RSYSLOG_FileFormat",
}

func (p *rsyslogRouting) line(line string) error {
	bad := func() error { return fmt.Errorf("rsyslog 配置超出已支持的传统本地路由子集") }
	p.lines++
	if p.lines > 4096 || len(line) > 4096 {
		return bad()
	}
	for _, b := range []byte(line) {
		if b != '\t' && (b < 32 || b > 126) {
			return bad()
		}
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	// Native legacy file actions consume the whole line. Reject their inline
	// comments; only module/global declarations have supported inline comments.
	declaration := strings.HasPrefix(line, "module(") || strings.HasPrefix(line, "$")
	if i := strings.IndexByte(line, '#'); i >= 0 {
		if !declaration || i == 0 || line[i-1] != ' ' && line[i-1] != '\t' {
			return bad()
		}
		line = strings.TrimSpace(line[:i])
	}
	if strings.HasPrefix(line, "module(") {
		p.previousRule = false
		switch line {
		case `module(load="imuxsock")`, `module(load="imuxsock" SysSock.Use="on")`, `module(load="imuxsock" SysSock.Use="off")`:
			if p.moduleSeen {
				return bad()
			}
			p.moduleSeen = true
			p.input = line != `module(load="imuxsock" SysSock.Use="off")`
		case `module(load="imklog" permitnonkernelfacility="on")`:
			if p.seen["imklog"] {
				return bad()
			}
			p.seen["imklog"] = true
		default:
			return bad()
		}
		return nil
	}
	if strings.HasPrefix(line, "$") {
		p.previousRule = false
		parts := strings.Fields(line)
		if len(parts) != 2 || p.seen[parts[0]] || !slices.Contains(strings.Split(rsyslogGlobals[parts[0]], "|"), parts[1]) || rsyslogGlobals[parts[0]] == "" {
			return bad()
		}
		p.seen[parts[0]] = true
		return nil
	}
	if line == "stop" {
		p.active = 0
		p.previousRule = false
		p.rules++
		return nil
	}
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return bad()
	}
	var mask uint8
	if parts[0] == "&" {
		if !p.previousRule {
			return bad()
		}
		mask = p.last
	} else {
		var err error
		mask, err = rsyslogCronSelector(parts[0])
		if err != nil {
			return bad()
		}
	}
	action := parts[1]
	if action == "~" || action == "stop" {
		p.active &^= mask
	} else if action == ":omusrmsg:*" {
		// A vendor notification action is never counted as a file route.
	} else {
		path := strings.TrimPrefix(action, "-")
		if !auditdLogPath(path) {
			return bad()
		}
		if path == "/var/log/cron.log" {
			p.covered |= mask & p.active
		}
	}
	p.last, p.previousRule = mask, true
	p.rules++
	return nil
}

var rsyslogIncludeName = regexp.MustCompile(`^[0-9]{2}-[A-Za-z0-9_-]{1,64}\.conf$`)
var rsyslogDirectoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func rsyslogNames(f *os.File) ([]string, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("无法枚举 rsyslog.d")
	}
	r := os.NewFile(uintptr(fd), "rsyslog.d")
	defer r.Close()
	names, err := r.Readdirnames(129)
	if err != nil && err != io.EOF || len(names) > 128 {
		return nil, fmt.Errorf("rsyslog.d 枚举异常或超过128条目")
	}
	prefixes := map[string]bool{}
	for _, name := range names {
		if !rsyslogDirectoryName.MatchString(name) {
			return nil, fmt.Errorf("rsyslog.d 文件名未支持")
		}
		// glob *.conf excludes dot files. Unique NN prefixes make supported
		// include order independent of suffix collation, without guessing locale.
		if !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".conf") {
			if !rsyslogIncludeName.MatchString(name) || prefixes[name[:2]] {
				return nil, fmt.Errorf("rsyslog 包含文件需唯一两位数字顺序前缀")
			}
			prefixes[name[:2]] = true
		}
	}
	slices.Sort(names)
	return names, nil
}

func rsyslogCronWithin(cs *CheckSpec, root string, probe func(context.Context, int) ItemResult) ItemResult {
	actual := "scope=on-disk-rsyslog-cron-routing loaded_state=unverified delivery_state=unverified"
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: actual, Message: message} }
	if !validRsyslogCron(cs) {
		return failure("rsyslog cron 路由参考定义无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	if r := probe(ctx, cs.TimeoutMs); r.Error {
		return failure(r.Message)
	}
	actual += " package=rsyslog version=" + rsyslogPackageVersion
	var entries []*cronMetadataEntry
	defer func() {
		for _, e := range entries {
			e.f.Close()
		}
	}()
	open := func(target string, directory bool) (*cronMetadataEntry, error) {
		f, parents, err := openLogPath(root, target)
		if err != nil {
			return nil, fmt.Errorf("rsyslog 配置缺失、含链接或无法打开：%s", target)
		}
		e := &cronMetadataEntry{f: f, target: target, parents: parents}
		entries = append(entries, e)
		if err := unix.Fstat(int(f.Fd()), &e.stat); err != nil {
			return nil, fmt.Errorf("无法确认 rsyslog 配置元数据")
		}
		kind := uint32(unix.S_IFREG)
		if directory {
			kind = unix.S_IFDIR
		}
		if e.stat.Mode&unix.S_IFMT != kind || !directory && e.stat.Nlink != 1 || e.stat.Uid != 0 || e.stat.Mode&0022 != 0 {
			return nil, fmt.Errorf("rsyslog 输入需 UID0、组和其他用户不可写的无链接普通配置/目录")
		}
		attrs := []string{"system.posix_acl_access"}
		if directory {
			attrs = append(attrs, "system.posix_acl_default")
		}
		for _, attr := range attrs {
			size, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), attr, nil)
			if err != nil && err != unix.ENODATA || size > 0 {
				return nil, fmt.Errorf("rsyslog 输入存在 ACL 或无法确认 ACL")
			}
		}
		return e, nil
	}
	p := &rsyslogRouting{active: 255, seen: map[string]bool{}}
	var dir *cronMetadataEntry
	var names []string
	bytesRead, files := 0, 0
	var parseFile func(string, bool) error
	parseFile = func(target string, included bool) error {
		if ctx.Err() != nil || files >= 33 {
			return fmt.Errorf("rsyslog 配置超时或超过32个包含文件")
		}
		e, err := open(target, false)
		if err != nil {
			return err
		}
		if e.stat.Size > 64*1024 {
			return fmt.Errorf("rsyslog 单文件超过64KiB")
		}
		fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", e.f.Fd()), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("无法读取固定 rsyslog 配置")
		}
		r := os.NewFile(uintptr(fd), target)
		raw, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
		r.Close()
		bytesRead += len(raw)
		files++
		if err != nil || len(raw) > 64*1024 || bytesRead > 256*1024 || ctx.Err() != nil || len(raw) > 0 && raw[len(raw)-1] != '\n' {
			return fmt.Errorf("rsyslog 配置读取异常、超限、未终止行或超时")
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
			// Includes are expanded exactly at their position, never collected
			// then applied after the main file. Nested/repeated includes error.
			trim := strings.TrimSpace(line)
			if trim == "$IncludeConfig /etc/rsyslog.d/*.conf" {
				if included || p.includeSeen {
					return fmt.Errorf("rsyslog 嵌套或重复包含未支持")
				}
				p.includeSeen = true
				dir, err = open("/etc/rsyslog.d", true)
				if err != nil {
					return err
				}
				names, err = rsyslogNames(dir.f)
				if err != nil {
					return err
				}
				for _, name := range names {
					if !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".conf") {
						if err := parseFile("/etc/rsyslog.d/"+name, true); err != nil {
							return err
						}
					}
				}
			} else if err := p.line(line); err != nil {
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
			return failure("rsyslog 配置期间被替换")
		}
		var current, held unix.Stat_t
		err = unix.Fstat(int(now.Fd()), &current)
		now.Close()
		heldErr := unix.Fstat(int(e.f.Fd()), &held)
		if err != nil || heldErr != nil || !sameCronStat(e.stat, current) || !sameCronStat(e.stat, held) || e.stat.Size != current.Size || e.stat.Mtim != current.Mtim || len(parents) != len(e.parents) {
			return failure("rsyslog 配置内容或元数据在检查期间变化")
		}
		for i := range parents {
			if !sameLogParent(parents[i], e.parents[i]) {
				return failure("rsyslog 父目录在检查期间变化")
			}
		}
	}
	if dir != nil {
		after, err := rsyslogNames(dir.f)
		if err != nil || !slices.Equal(names, after) {
			return failure("rsyslog 包含条目在检查期间变化")
		}
	}
	if ctx.Err() != nil {
		return failure("rsyslog 配置检查超时")
	}
	actual += fmt.Sprintf(" imuxsock=%t destination=/var/log/cron.log covered_mask=0x%02x missing_mask=0x%02x files=%d rules=%d", p.input, p.covered, ^p.covered, files, p.rules)
	passed := p.input && p.covered == 255
	message := ""
	if !passed {
		message = "Cron dedicated log routing reference mismatch"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}

func sameLogParent(a, b unix.Stat_t) bool {
	// Directory contents elsewhere are outside the read graph; identity and
	// access metadata are checked, and the actual include directory also has
	// its mtime/name collection checked above.
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Ctim == b.Ctim
}
