//go:build linux

package baseline

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixtureAuditWatch(path string, perm, action uint32) []byte {
	b := make([]byte, auditRuleSize+len(path))
	put := func(off int, value uint32) { binary.NativeEndian.PutUint32(b[off:], value) }
	put(0, unix.AUDIT_FILTER_EXIT)
	put(4, action)
	put(8, 2)
	for i := 0; i < 64; i++ {
		put(12+4*i, ^uint32(0))
	}
	put(264, 0x0000ffff)
	put(268, unix.AUDIT_WATCH)
	put(524, uint32(len(path)))
	put(780, unix.AUDIT_EQUAL)
	put(272, unix.AUDIT_PERM)
	put(528, perm)
	put(784, unix.AUDIT_EQUAL)
	put(1036, uint32(len(path)))
	copy(b[auditRuleSize:], path)
	return b
}

func TestAuditStatusIsEnabledEvidenceNotDaemonPresence(t *testing.T) {
	for _, enabled := range []uint32{0, 1, 2} {
		data := make([]byte, 44)
		binary.NativeEndian.PutUint32(data[4:], enabled)
		binary.NativeEndian.PutUint32(data[24:], 17)
		st, err := parseAuditStatus(data)
		if err != nil {
			t.Fatal(err)
		}
		r := auditStatusResult(st)
		if r.Error || r.Passed != (enabled != 0) || !strings.Contains(r.Actual, "daemon_pid=0 lost=17") {
			t.Fatal(r)
		}
	}
	for _, size := range []int{0, 40, 48} {
		if _, err := parseAuditStatus(make([]byte, size)); err == nil {
			t.Fatal("accepted unknown layout", size)
		}
	}
	for _, off := range []int{4, 8} {
		data := make([]byte, 44)
		binary.NativeEndian.PutUint32(data[off:], 3)
		if _, err := parseAuditStatus(data); err == nil {
			t.Fatal("accepted invalid enum")
		}
	}
}

func TestAuditWatchesRequireAllPathsAndPreserveAction(t *testing.T) {
	targets := []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"}
	var rules [][]byte
	for _, path := range targets {
		rules = append(rules, fixtureAuditWatch(path, 10, unix.AUDIT_ALWAYS))
	}
	for _, enabled := range []uint32{0, 1, 2} {
		r := evaluateAuditWatches(auditStatus{enabled: enabled}, rules, targets)
		if r.Error || r.Passed != (enabled != 0) {
			t.Fatal(r)
		}
	}
	missing := evaluateAuditWatches(auditStatus{enabled: 1}, rules[:3], targets)
	if missing.Error || missing.Passed || !strings.Contains(missing.Actual, "/etc/gshadow=none") {
		t.Fatal(missing)
	}
	rules[0] = fixtureAuditWatch(targets[0], 2, unix.AUDIT_ALWAYS)
	r := evaluateAuditWatches(auditStatus{enabled: 1}, rules, targets)
	if r.Error || r.Passed || !strings.Contains(r.Actual, "/etc/passwd=w") {
		t.Fatal(r)
	}
	rules = append(rules, fixtureAuditWatch(targets[0], 8, unix.AUDIT_ALWAYS))
	if r := evaluateAuditWatches(auditStatus{enabled: 1}, rules, targets); r.Error || !r.Passed {
		t.Fatal(r)
	}
	// auditctl's watch pretty-printer can erase this action. Raw data must not.
	rules = append(rules, fixtureAuditWatch("/tmp/unrelated", 10, unix.AUDIT_NEVER))
	if r := evaluateAuditWatches(auditStatus{enabled: 1}, rules, targets); !r.Error || r.Passed {
		t.Fatal(r)
	}
}

func TestAuditUnknownRulesAndMalformedStringsFailClosed(t *testing.T) {
	for _, off := range []int{0, 4, 8, 12, 268, 524, 780, 1036} {
		b := fixtureAuditWatch("/etc/passwd", 10, unix.AUDIT_ALWAYS)
		binary.NativeEndian.PutUint32(b[off:], 123)
		if _, _, err := parseAuditWatch(b); err == nil {
			t.Fatal("accepted unsupported field", off)
		}
	}
	for _, path := range []string{"relative", "/", "/etc/../etc/passwd", "/etc/secret\x00", "/etc/secret\n"} {
		if _, _, err := parseAuditWatch(fixtureAuditWatch(path, 10, unix.AUDIT_ALWAYS)); err == nil {
			t.Fatal("accepted path", path)
		}
	}
	for _, perm := range []uint32{0, 16} {
		if _, _, err := parseAuditWatch(fixtureAuditWatch("/etc/passwd", perm, unix.AUDIT_ALWAYS)); err == nil {
			t.Fatal("accepted perm")
		}
	}
	for _, size := range []int{0, 16, 1039} {
		if _, _, err := parseAuditWatch(make([]byte, size)); err == nil {
			t.Fatal("accepted truncated rule")
		}
	}
	b := fixtureAuditWatch("/etc/passwd", 10, unix.AUDIT_ALWAYS)
	key := "DO_NOT_REPORT_AUDIT_KEY"
	b = append(b, []byte(key)...)
	binary.NativeEndian.PutUint32(b[8:], 3)
	binary.NativeEndian.PutUint32(b[276:], unix.AUDIT_FILTERKEY)
	binary.NativeEndian.PutUint32(b[532:], uint32(len(key)))
	binary.NativeEndian.PutUint32(b[788:], unix.AUDIT_EQUAL)
	binary.NativeEndian.PutUint32(b[1036:], uint32(len(b)-auditRuleSize))
	r := evaluateAuditWatches(auditStatus{enabled: 1}, [][]byte{b}, []string{"/etc/passwd"})
	if r.Error || !r.Passed || strings.Contains(r.Actual, "DO_NOT_REPORT") {
		t.Fatal(r)
	}
}

func TestAuditNetlinkEnvelopeRejectsTruncationAndForeignMessages(t *testing.T) {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint32(b, 20)
	binary.NativeEndian.PutUint32(b[8:], 7)
	if _, err := parseAuditDatagram(b, 7, 99); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		off   int
		value uint32
	}{{0, 0}, {0, 16}, {0, 21}, {8, 8}, {12, 1}} {
		c := append([]byte(nil), b...)
		binary.NativeEndian.PutUint32(c[change.off:], change.value)
		if _, err := parseAuditDatagram(c, 7, 99); err == nil {
			t.Fatal("accepted envelope", change)
		}
	}
	ack := make([]byte, 20)
	binary.NativeEndian.PutUint32(ack, 20)
	binary.NativeEndian.PutUint16(ack[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(ack[8:], 7)
	binary.NativeEndian.PutUint32(ack[12:], 99)
	if _, err := parseAuditDatagram(ack, 7, 99); err != nil {
		t.Fatal(err)
	}
	if _, err := parseAuditDatagram(ack, 7, 98); err == nil {
		t.Fatal("accepted ACK for another port")
	}
	for _, data := range [][]byte{nil, b[:15], b[:19]} {
		if _, err := parseAuditDatagram(data, 7, 99); err == nil {
			t.Fatal("accepted incomplete message")
		}
	}
	if sameAuditRules([][]byte{{1}, {2}}, [][]byte{{2}, {1}}) || sameAuditRules(nil, [][]byte{{1}}) {
		t.Fatal("rule order/change lost")
	}
	s := &auditSocket{fd: -1, deadline: time.Now().Add(-time.Second)}
	if _, err := s.query(unix.AUDIT_SET); err == nil {
		t.Fatal("allowed mutation")
	}
	if _, err := s.query(unix.AUDIT_GET); err == nil {
		t.Fatal("ignored deadline")
	}
}

func TestKernelAuditPermissionBoundaryHasNoFallback(t *testing.T) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	var caps uint64
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			caps, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if caps&(1<<30) != 0 {
		t.Skip("unprivileged kernel-query boundary")
	}
	r := checkLinuxAudit(&CheckSpec{Type: "linux_audit", Target: "kernel", Option: "enabled", Operator: "eq", Expected: auditReference("enabled"), TimeoutMs: 1000})
	if !r.Error || r.Passed {
		t.Fatal("kernel query without CAP_AUDIT_CONTROL passed", r)
	}
	t.Logf("unprivileged kernel audit evidence: %+v", r)
}
