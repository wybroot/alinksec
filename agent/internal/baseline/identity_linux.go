//go:build linux

package baseline

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var identityName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?$`)
var identityNumber = regexp.MustCompile(`^[0-9]+$`)

type localAccount struct {
	name          string
	uid           uint32
	shell         string
	empty, shadow bool
}

// Production callers supply only the four fixed local identity paths. Tests
// substitute isolated files; package input cannot change these dependencies.
type identityPaths struct{ passwd, shadow, group, gshadow string }

var systemIdentityPaths = identityPaths{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"}

func stableIdentity(path string, before, after os.FileInfo) bool {
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() {
		return false
	}
	b, a, c := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t), current.Sys().(*syscall.Stat_t)
	return b.Dev == a.Dev && b.Ino == a.Ino && a.Dev == c.Dev && a.Ino == c.Ino &&
		b.Size == a.Size && b.Mtim == a.Mtim && b.Ctim == a.Ctim && a.Ctim == c.Ctim
}

func checkLocalIdentity(cs *CheckSpec) ItemResult {
	return localIdentityWithin(cs, systemIdentityPaths)
}

func openIdentity(path string, metadata bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if metadata {
		flags = unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("无法读取身份文件 %s", path)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		f.Close()
		return nil, fmt.Errorf("身份文件 %s 必须为不超过 8 MiB 的普通文件，且不能为链接", path)
	}
	return f, nil
}

func scanIdentity(path string, fields int, deadline time.Time, visit func([]string) error) error {
	f, err := openIdentity(path, false)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return fmt.Errorf("无法取得身份文件元数据")
	}
	limited := &io.LimitedReader{R: f, N: maxFileBytes + 1}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 4096), 16*1024)
	count := 0
	for scan.Scan() {
		count++
		if count > 16384 || time.Now().After(deadline) {
			return fmt.Errorf("身份文件读取超过行数或时间上限")
		}
		line := scan.Text()
		valid := utf8.ValidString(line) && !strings.ContainsFunc(line, func(r rune) bool { return r < 32 || r == 127 })
		parts := strings.Split(line, ":")
		// Never include a line, a password field or a scanner error in evidence.
		if !valid || len(parts) != fields || !identityName.MatchString(parts[0]) {
			return fmt.Errorf("身份文件 %s 第 %d 行格式无效", path, count)
		}
		if err := visit(parts); err != nil {
			return fmt.Errorf("身份文件 %s 第 %d 行: %s", path, count, err)
		}
	}
	if scan.Err() != nil || limited.N == 0 || count == 0 || time.Now().After(deadline) {
		return fmt.Errorf("身份文件 %s 为空、读取失败或超过资源上限", path)
	}
	after, err := f.Stat()
	if err != nil || !stableIdentity(path, before, after) {
		return fmt.Errorf("身份文件 %s 在读取期间发生变化", path)
	}
	return nil
}

func identityID(value string) (uint32, error) {
	if !identityNumber.MatchString(value) {
		return 0, fmt.Errorf("UID/GID 需为十进制非负整数")
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == uint64(^uint32(0)) {
		return 0, fmt.Errorf("UID/GID 超出支持范围")
	}
	return uint32(n), nil
}

func readLocalAccounts(path string, deadline time.Time) ([]localAccount, error) {
	var accounts []localAccount
	names := map[string]bool{}
	err := scanIdentity(path, 7, deadline, func(p []string) error {
		if names[p[0]] {
			return fmt.Errorf("账户名称重复")
		}
		names[strings.Clone(p[0])] = true
		uid, err := identityID(p[2])
		if err != nil {
			return err
		}
		if _, err := identityID(p[3]); err != nil {
			return err
		}
		accounts = append(accounts, localAccount{name: strings.Clone(p[0]), uid: uid, shell: strings.Clone(p[6]), empty: p[1] == "", shadow: p[1] == "x"})
		return nil
	})
	return accounts, err
}

func identityGroup(path, name string, deadline time.Time) (uint32, error) {
	var gid uint32
	found := false
	names := map[string]bool{}
	err := scanIdentity(path, 4, deadline, func(p []string) error {
		if names[p[0]] {
			return fmt.Errorf("属组名称重复")
		}
		names[strings.Clone(p[0])] = true
		id, err := identityID(p[2])
		if err != nil {
			return err
		}
		if p[0] == name {
			gid, found = id, true
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("本地 group 中缺少要求的属组")
	}
	return gid, nil
}

func identityTarget(target string, paths identityPaths) string {
	switch target {
	case "/etc/passwd":
		return paths.passwd
	case "/etc/shadow":
		return paths.shadow
	case "/etc/group":
		return paths.group
	case "/etc/gshadow":
		return paths.gshadow
	}
	return ""
}

func localIdentityWithin(cs *CheckSpec, paths identityPaths) ItemResult {
	deadline := time.Now().Add(time.Duration(cs.TimeoutMs) * time.Millisecond)
	prefix := "scope=local-files target=" + cs.Target + " "
	fail := func(err error) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: err.Error()} }
	if cs.Type == "local_identity_file" {
		f, err := openIdentity(identityTarget(cs.Target, paths), true)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return fail(fmt.Errorf("无法取得身份文件元数据"))
		}
		st := info.Sys().(*syscall.Stat_t)
		mode := st.Mode & 07777
		actual := fmt.Sprintf("%smode=%04o uid=%d gid=%d", prefix, mode, st.Uid, st.Gid)
		// POSIX mode bits do not describe all grants in an extended access ACL.
		// O_PATH permits metadata checks even for mode 0000. Resolve the held
		// descriptor through procfs so ACL lookup stays on the same inode.
		size, aclErr := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), "system.posix_acl_access", nil)
		if aclErr != nil && aclErr != unix.ENODATA || size > 0 {
			return ItemResult{Error: true, Actual: actual + " access_acl=unconfirmed", Message: "存在扩展访问 ACL 或无法确认 ACL；本参考包不据此判断完整访问权限"}
		}
		expectedGID := uint32(0)
		if cs.Group == "shadow" {
			expectedGID, err = identityGroup(paths.group, "shadow", deadline)
			if err != nil {
				return fail(err)
			}
		}
		allowed, err := strconv.ParseUint(cs.Perm, 8, 16)
		if err != nil {
			return fail(fmt.Errorf("权限上限无效"))
		}
		actual += fmt.Sprintf(" access_acl=none allowed_mode=%s expected_uid=0 expected_gid=%d", cs.Perm, expectedGID)
		if time.Now().After(deadline) {
			return fail(fmt.Errorf("身份文件检查超时"))
		}
		after, err := f.Stat()
		if err != nil || !stableIdentity(identityTarget(cs.Target, paths), info, after) {
			return fail(fmt.Errorf("身份文件在检查期间发生变化"))
		}
		passed := mode & ^uint32(allowed) == 0 && st.Uid == 0 && st.Gid == expectedGID
		result := ItemResult{Passed: passed, Actual: actual}
		if !passed {
			result.Message = "身份文件的权限超出允许位，或数值属主/属组不满足参考策略"
		}
		return result
	}
	accounts, err := readLocalAccounts(paths.passwd, deadline)
	if err != nil {
		return fail(err)
	}
	var offenders []string
	checked := 0
	switch cs.Option {
	case "uid0_accounts":
		for _, account := range accounts {
			if account.uid == 0 {
				offenders = append(offenders, account.name)
			}
		}
		sort.Strings(offenders)
		passed := len(offenders) == 1 && offenders[0] == "root"
		result := ItemResult{Passed: passed, Actual: fmt.Sprintf("%saccounts=%d uid0_count=%d uid0_accounts=[%s] expected=root", prefix, len(accounts), len(offenders), strings.Join(offenders, ","))}
		if !passed {
			result.Message = "本地 passwd 的 UID 0 账户必须恰好为 root"
		}
		return result
	case "system_shells":
		if cs.UIDMin == nil || cs.UIDMax == nil {
			return fail(fmt.Errorf("账户范围缺失"))
		}
		for _, account := range accounts {
			if account.uid < *cs.UIDMin || account.uid > *cs.UIDMax {
				continue
			}
			checked++
			switch account.shell {
			case "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
			default:
				offenders = append(offenders, fmt.Sprintf("%s(uid=%d)", account.name, account.uid))
			}
		}
		prefix += fmt.Sprintf("uid_range=%d..%d checked=%d ", *cs.UIDMin, *cs.UIDMax, checked)
	case "empty_password":
		passwd := map[string]localAccount{}
		shadow := map[string]bool{}
		for _, account := range accounts {
			passwd[account.name] = account
			if account.empty {
				offenders = append(offenders, "passwd:"+account.name)
			}
		}
		err := scanIdentity(paths.shadow, 9, deadline, func(p []string) error {
			if _, found := shadow[p[0]]; found {
				return fmt.Errorf("shadow 账户名称重复")
			}
			if _, found := passwd[p[0]]; !found {
				return fmt.Errorf("shadow 账户缺少对应 passwd 记录")
			}
			shadow[strings.Clone(p[0])] = true
			if p[1] == "" {
				offenders = append(offenders, "shadow:"+p[0])
			}
			return nil
		})
		if err != nil {
			return fail(err)
		}
		for _, account := range accounts {
			if account.shadow && !shadow[account.name] {
				return fail(fmt.Errorf("使用 shadow 的 passwd 账户缺少对应记录"))
			}
		}
		prefix += fmt.Sprintf("passwd_accounts=%d shadow_accounts=%d ", len(accounts), len(shadow))
	default:
		return fail(fmt.Errorf("本地账户检查项尚未支持"))
	}
	sort.Strings(offenders)
	result := ItemResult{Passed: len(offenders) == 0, Actual: fmt.Sprintf("%soffender_count=%d accounts=[%s]", prefix, len(offenders), strings.Join(offenders, ","))}
	if !result.Passed {
		result.Message = "本地身份文件存在不满足参考策略的账户；不代表实际认证链或外部身份源结论"
	}
	return result
}
