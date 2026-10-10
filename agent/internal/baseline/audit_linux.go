//go:build linux

package baseline

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Linux UAPI audit_rule_data: 3 words, four 64-word arrays, buflen, strings.
// Production sends only AUDIT_GET and AUDIT_LIST_RULES, never SET/ADD/DELETE,
// registration of a daemon PID, or subscription to event streams.
const auditRuleSize = 1040
const auditResponseLimit = 512 * 1024
const auditRuleLimit = 256

type auditSocket struct {
	fd       int
	seq      uint32
	port     uint32
	deadline time.Time
}

func newAuditSocket(deadline time.Time) (*auditSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_AUDIT)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("审计查询端口无效")
	}
	return &auditSocket{fd: fd, port: local.Pid, deadline: deadline}, nil
}

func (s *auditSocket) ready(events int16) error {
	for {
		remaining := time.Until(s.deadline)
		if remaining <= 0 {
			return fmt.Errorf("审计查询超时")
		}
		p := []unix.PollFd{{Fd: int32(s.fd), Events: events}}
		n, err := unix.Poll(p, int((remaining+time.Millisecond-1)/time.Millisecond))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("审计查询超时")
		}
		if p[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("审计查询连接异常")
		}
		if p[0].Revents&events != 0 {
			return nil
		}
	}
}

type auditMessage struct {
	kind, flags uint16
	data        []byte
}

func parseAuditDatagram(data []byte, seq, port uint32) ([]auditMessage, error) {
	var messages []auditMessage
	for len(data) > 0 {
		if len(data) < 16 {
			return nil, fmt.Errorf("审计消息头不完整")
		}
		n := int(binary.NativeEndian.Uint32(data))
		if n < 16 || n > len(data) || (n+3)&^3 > len(data) {
			return nil, fmt.Errorf("审计消息长度无效或被截断")
		}
		// Audit data uses header PID 0; netlink_ack addresses NLMSG_ERROR to
		// our bound port. Sender authentication comes from recvmsg sockaddr.
		kind := binary.NativeEndian.Uint16(data[4:])
		expectedPort := uint32(0)
		if kind == unix.NLMSG_ERROR {
			expectedPort = port
		}
		if binary.NativeEndian.Uint32(data[8:]) != seq || binary.NativeEndian.Uint32(data[12:]) != expectedPort {
			return nil, fmt.Errorf("审计响应序号或内核来源不符")
		}
		messages = append(messages, auditMessage{binary.NativeEndian.Uint16(data[4:]), binary.NativeEndian.Uint16(data[6:]), bytes.Clone(data[16:n])})
		data = data[(n+3)&^3:]
	}
	if len(messages) == 0 {
		return nil, fmt.Errorf("审计响应为空")
	}
	return messages, nil
}

func (s *auditSocket) query(kind uint16) ([][]byte, error) {
	if kind != unix.AUDIT_GET && kind != unix.AUDIT_LIST_RULES {
		return nil, fmt.Errorf("禁止非只读审计查询")
	}
	s.seq++
	req := make([]byte, 16)
	binary.NativeEndian.PutUint32(req, 16)
	binary.NativeEndian.PutUint16(req[4:], kind)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(req[8:], s.seq)
	for {
		if err := s.ready(unix.POLLOUT); err != nil {
			return nil, err
		}
		err := unix.Sendto(s.fd, req, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	var replies [][]byte
	total := 0
	buf := make([]byte, 16*1024)
	for {
		if err := s.ready(unix.POLLIN); err != nil {
			return nil, err
		}
		n, _, flags, from, err := unix.Recvmsg(s.fd, buf, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		origin, ok := from.(*unix.SockaddrNetlink)
		if !ok || origin.Pid != 0 || origin.Groups != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return nil, fmt.Errorf("审计响应并非完整内核单播消息")
		}
		total += n
		if total > auditResponseLimit {
			return nil, fmt.Errorf("审计响应超过 512 KiB 上限")
		}
		messages, err := parseAuditDatagram(buf[:n], s.seq, s.port)
		if err != nil {
			return nil, err
		}
		done := false
		for _, m := range messages {
			if done {
				return nil, fmt.Errorf("审计响应完成后仍有数据")
			}
			if m.kind == unix.NLMSG_ERROR {
				if len(m.data) < 4 {
					return nil, fmt.Errorf("审计错误响应不完整")
				}
				code := int32(binary.NativeEndian.Uint32(m.data))
				if code >= 0 {
					return nil, fmt.Errorf("审计查询收到意外确认响应")
				}
				return nil, fmt.Errorf("内核审计查询失败: %s", unix.Errno(-int64(code)))
			}
			if kind == unix.AUDIT_GET {
				if m.kind != kind || m.flags != 0 || len(replies) != 0 {
					return nil, fmt.Errorf("审计状态响应类型、标志或数量异常")
				}
				replies = append(replies, m.data)
				done = true
			} else {
				if m.flags != unix.NLM_F_MULTI {
					return nil, fmt.Errorf("审计规则响应未完整分段或已中断")
				}
				if m.kind == unix.NLMSG_DONE {
					if len(m.data) != 0 {
						return nil, fmt.Errorf("审计规则结束响应无效")
					}
					done = true
				} else {
					if m.kind != kind || len(replies) >= auditRuleLimit {
						return nil, fmt.Errorf("审计规则类型无效或超过 256 条上限")
					}
					replies = append(replies, m.data)
				}
			}
		}
		if done {
			return replies, nil
		}
	}
}

type auditStatus struct{ enabled, pid, lost, backlog uint32 }

func (s *auditSocket) status() (auditStatus, error) {
	r, err := s.query(unix.AUDIT_GET)
	if err != nil {
		return auditStatus{}, err
	}
	return parseAuditStatus(r[0])
}

func parseAuditStatus(data []byte) (auditStatus, error) {
	if len(data) != 44 || binary.NativeEndian.Uint32(data[4:]) > 2 || binary.NativeEndian.Uint32(data[8:]) > 2 {
		return auditStatus{}, fmt.Errorf("内核审计状态布局或状态值尚未支持")
	}
	return auditStatus{binary.NativeEndian.Uint32(data[4:]), binary.NativeEndian.Uint32(data[12:]), binary.NativeEndian.Uint32(data[24:]), binary.NativeEndian.Uint32(data[28:])}, nil
}

func auditStatusResult(st auditStatus) ItemResult {
	actual := fmt.Sprintf("scope=kernel-audit enabled=%d daemon_pid=%d lost=%d backlog=%d", st.enabled, st.pid, st.lost, st.backlog)
	r := ItemResult{Passed: st.enabled == 1 || st.enabled == 2, Actual: actual}
	if !r.Passed {
		r.Message = "内核审计当前禁用；客户端安装与守护进程状态不代替启用证据"
	}
	return r
}

// A deliberately narrow, action-preserving reference: unfiltered always/exit
// watches, all syscall mask words, equal path/perm and an optional opaque key.
// Any other rule (including never/task/exclude, arch/UID filters, directory or
// syscall-specific forms) makes global coverage uncertain, hence error.
func parseAuditWatch(data []byte) (string, uint32, error) {
	bad := func() (string, uint32, error) {
		return "", 0, fmt.Errorf("存在抑制规则或尚未支持的审计规则形式，无法确认全局身份文件覆盖")
	}
	if len(data) < auditRuleSize || int(binary.NativeEndian.Uint32(data[1036:])) != len(data)-auditRuleSize {
		return bad()
	}
	word := func(off int) uint32 { return binary.NativeEndian.Uint32(data[off:]) }
	count := int(word(8))
	if word(0) != unix.AUDIT_FILTER_EXIT || word(4) != unix.AUDIT_ALWAYS || count < 2 || count > 3 {
		return bad()
	}
	for i := 0; i < 63; i++ {
		if word(12+4*i) != ^uint32(0) {
			return bad()
		}
	}
	// The kernel expands and clears the final 16 reserved syscall-class bits.
	if word(264) != 0x0000ffff {
		return bad()
	}
	seen := map[uint32]bool{}
	path, perm, offset := "", uint32(0), auditRuleSize
	for i := 0; i < count; i++ {
		field, value := word(268+4*i), word(524+4*i)
		if seen[field] || word(780+4*i) != unix.AUDIT_EQUAL {
			return bad()
		}
		seen[field] = true
		switch field {
		case unix.AUDIT_WATCH, unix.AUDIT_FILTERKEY:
			if value == 0 || uint64(offset)+uint64(value) > uint64(len(data)) {
				return bad()
			}
			str := string(data[offset : offset+int(value)])
			offset += int(value)
			if !utf8.ValidString(str) || strings.ContainsAny(str, "\x00\r\n") {
				return bad()
			}
			if field == unix.AUDIT_WATCH {
				if !filepath.IsAbs(str) || filepath.Clean(str) != str || str == "/" {
					return bad()
				}
				path = str
			}
		case unix.AUDIT_PERM:
			if value == 0 || value & ^uint32(15) != 0 {
				return bad()
			}
			perm = value
		default:
			return bad()
		}
	}
	if offset != len(data) || path == "" || perm == 0 {
		return bad()
	}
	return path, perm, nil
}

func evaluateAuditWatches(st auditStatus, rules [][]byte, targets []string) ItemResult {
	r := auditStatusResult(st)
	r.Actual += fmt.Sprintf(" rules=%d reference=always_exit_all identity_watches=wa", len(rules))
	coverage := map[string]uint32{}
	for _, data := range rules {
		path, perm, err := parseAuditWatch(data)
		if err != nil {
			r.Passed = false
			r.Error = true
			r.Message = err.Error()
			return r
		}
		coverage[path] |= perm
	}
	for _, path := range targets {
		p := coverage[path] & (unix.AUDIT_PERM_WRITE | unix.AUDIT_PERM_ATTR)
		value := "none"
		if p == unix.AUDIT_PERM_WRITE {
			value = "w"
		}
		if p == unix.AUDIT_PERM_ATTR {
			value = "a"
		}
		if p == unix.AUDIT_PERM_WRITE|unix.AUDIT_PERM_ATTR {
			value = "wa"
		}
		r.Actual += " " + path + "=" + value
		if value != "wa" {
			r.Passed = false
		}
	}
	if !r.Passed {
		r.Message = "内核审计禁用或当前加载的身份文件 watch 未覆盖全部写入与属性变更参考"
	}
	return r
}

func checkLinuxAudit(cs *CheckSpec) ItemResult {
	prefix := "scope=kernel-audit option=" + cs.Option
	fail := func(err error) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: err.Error()} }
	if cs.Target != "kernel" || auditReference(cs.Option) == "" || cs.Expected != auditReference(cs.Option) || cs.Operator != "eq" {
		return fail(fmt.Errorf("内核审计参考定义无效"))
	}
	s, err := newAuditSocket(time.Now().Add(time.Duration(cs.TimeoutMs) * time.Millisecond))
	if err != nil {
		return fail(fmt.Errorf("无法打开内核审计查询: %w", err))
	}
	defer unix.Close(s.fd)
	before, err := s.status()
	if err != nil {
		return fail(err)
	}
	if cs.Option == "enabled" {
		return auditStatusResult(before)
	}
	targets := []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"}
	// Hold and reopen each path: never read credential contents or follow links.
	var identities [][]uint64
	for _, target := range targets {
		f, parents, err := openLogPath("/", target)
		if err != nil {
			return fail(fmt.Errorf("身份文件路径无法确认"))
		}
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		defer f.Close()
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
			return fail(fmt.Errorf("身份文件不是无链接的普通文件"))
		}
		ids := []uint64{uint64(st.Dev), st.Ino}
		for _, parent := range parents {
			ids = append(ids, uint64(parent.Dev), parent.Ino)
		}
		identities = append(identities, ids)
	}
	rules, err := s.query(unix.AUDIT_LIST_RULES)
	if err != nil {
		return fail(err)
	}
	repeat, err := s.query(unix.AUDIT_LIST_RULES)
	if err != nil {
		return fail(err)
	}
	after, err := s.status()
	if err != nil {
		return fail(err)
	}
	if before.enabled != after.enabled || !sameAuditRules(rules, repeat) {
		return fail(fmt.Errorf("内核审计状态或规则在检查期间发生变化，请重试"))
	}
	for i, target := range targets {
		f, parents, err := openLogPath("/", target)
		if err != nil {
			return fail(fmt.Errorf("身份文件路径发生变化"))
		}
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		ids := identities[i]
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || len(ids) != 2+2*len(parents) || ids[0] != uint64(st.Dev) || ids[1] != st.Ino {
			return fail(fmt.Errorf("身份文件路径发生变化"))
		}
		for j, parent := range parents {
			if ids[2+2*j] != uint64(parent.Dev) || ids[3+2*j] != parent.Ino {
				return fail(fmt.Errorf("身份文件父目录发生变化"))
			}
		}
	}
	if time.Now().After(s.deadline) {
		return fail(fmt.Errorf("审计查询超时"))
	}
	return evaluateAuditWatches(before, rules, targets)
}

func sameAuditRules(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
