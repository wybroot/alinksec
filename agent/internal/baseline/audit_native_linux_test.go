//go:build linux

package baseline

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Mutating netlink requests exist only in this test binary and only touch rules
// for files created below t.TempDir. Never clear rules or change audit enabled.
func nativeAuditMutation(s *auditSocket, kind uint16, rule []byte) error {
	s.seq++
	b := make([]byte, 16+len(rule))
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], kind)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(b[8:], s.seq)
	copy(b[16:], rule)
	if err := s.ready(unix.POLLOUT); err != nil {
		return err
	}
	if err := unix.Sendto(s.fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if err := s.ready(unix.POLLIN); err != nil {
		return err
	}
	buf := make([]byte, 16*1024)
	n, _, flags, from, err := unix.Recvmsg(s.fd, buf, nil, 0)
	if err != nil {
		return err
	}
	origin, ok := from.(*unix.SockaddrNetlink)
	if !ok || origin.Pid != 0 || origin.Groups != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return unix.EPROTO
	}
	ms, err := parseAuditDatagram(buf[:n], s.seq, s.port)
	if err != nil {
		return err
	}
	if len(ms) != 1 || ms[0].kind != unix.NLMSG_ERROR || len(ms[0].data) < 4 {
		return unix.EPROTO
	}
	code := int32(binary.NativeEndian.Uint32(ms[0].data))
	if code != 0 {
		return unix.Errno(-int64(code))
	}
	return nil
}

func TestNativeKernelAudit(t *testing.T) {
	if os.Getenv("ALINKSEC_AUDIT_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable runner validation required")
	}
	if os.Getenv("ALINKSEC_AUDIT_FIXTURES_ALLOWED") != "true" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Geteuid() != 0 {
		t.Fatal("native fixture authorization requires disposable hosted root runner")
	}
	s, err := newAuditSocket(time.Now().Add(45 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(s.fd)
	st, err := s.status()
	if err != nil {
		t.Fatal("required kernel audit query", err)
	}
	if st.enabled == 2 {
		t.Fatal("immutable audit state prevents isolated fixture validation; no state change attempted")
	}
	original, err := s.query(unix.AUDIT_LIST_RULES)
	if err != nil {
		t.Fatal(err)
	}
	cs := &CheckSpec{Type: "linux_audit", Target: "kernel", Option: "enabled", Operator: "eq", Expected: auditReference("enabled"), TimeoutMs: 5000}
	observed := checkLinuxAudit(cs)
	if observed.Error || observed.Passed != (st.enabled != 0) {
		t.Fatal(observed)
	}
	t.Logf("AUDIT_NATIVE_STATUS enabled=%d result=%+v", st.enabled, observed)
	cs.Option = "identity_watches"
	cs.Expected = auditReference(cs.Option)
	t.Logf("AUDIT_NATIVE_HOST_IDENTITY observation_only=%+v", checkLinuxAudit(cs))
	root := t.TempDir()
	var targets []string
	var added [][]byte
	defer func() {
		cleanup, err := newAuditSocket(time.Now().Add(10 * time.Second))
		if err != nil {
			t.Errorf("cleanup socket: %v", err)
			return
		}
		defer unix.Close(cleanup.fd)
		for i := len(added) - 1; i >= 0; i-- {
			if err := nativeAuditMutation(cleanup, unix.AUDIT_DEL_RULE, added[i]); err != nil && err != unix.ENOENT {
				t.Errorf("remove own fixture rule: %v", err)
			}
		}
		after, err := cleanup.query(unix.AUDIT_LIST_RULES)
		if err != nil || !sameAuditRules(original, after) {
			t.Errorf("existing audit rules changed or fixture not cleaned: %v", err)
		}
		current, err := cleanup.status()
		if err != nil || current.enabled != st.enabled {
			t.Errorf("audit enabled changed: %v", err)
		}
	}()
	for _, name := range []string{"passwd", "shadow", "group", "gshadow"} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, path)
		rule := fixtureAuditWatch(path, 10, unix.AUDIT_ALWAYS)
		added = append(added, rule)
		if err := nativeAuditMutation(s, unix.AUDIT_ADD_RULE, rule); err != nil {
			t.Fatal("add only private watch", err)
		}
	}
	selectOwn := func() [][]byte {
		all, err := s.query(unix.AUDIT_LIST_RULES)
		if err != nil {
			t.Fatal(err)
		}
		var own [][]byte
		for _, rule := range all {
			if len(rule) >= auditRuleSize && strings.Contains(string(rule[auditRuleSize:]), root+"/") {
				own = append(own, rule)
			}
		}
		return own
	}
	own := selectOwn()
	if len(own) != 4 {
		t.Fatalf("actual kernel returned %d own rules", len(own))
	}
	// Coverage assertion isolates our four rules and assumes enabled=1 explicitly;
	// it never certifies the host's global state or changes its enabled flag.
	r := evaluateAuditWatches(auditStatus{enabled: 1}, own, targets)
	if r.Error || !r.Passed {
		t.Fatal("actual binary watch roundtrip", r)
	}
	t.Logf("AUDIT_NATIVE_PRIVATE_COMPLETE assumed_enabled=1 rules=4 result=%+v", r)
	if r := evaluateAuditWatches(auditStatus{enabled: 1}, own[:3], targets); r.Error || r.Passed {
		t.Fatal("missing private watch", r)
	}
	if err := nativeAuditMutation(s, unix.AUDIT_DEL_RULE, added[0]); err != nil {
		t.Fatal(err)
	}
	added = added[1:]
	weak := fixtureAuditWatch(targets[0], 2, unix.AUDIT_ALWAYS)
	added = append(added, weak)
	if err := nativeAuditMutation(s, unix.AUDIT_ADD_RULE, weak); err != nil {
		t.Fatal(err)
	}
	if r := evaluateAuditWatches(auditStatus{enabled: 1}, selectOwn(), targets); r.Error || r.Passed {
		t.Fatal("actual missing attribute mask", r)
	}
	extra := filepath.Join(root, "suppressed")
	if err := os.WriteFile(extra, nil, 0600); err != nil {
		t.Fatal(err)
	}
	never := fixtureAuditWatch(extra, 10, unix.AUDIT_NEVER)
	added = append(added, never)
	if err := nativeAuditMutation(s, unix.AUDIT_ADD_RULE, never); err != nil {
		t.Fatal(err)
	}
	if r := evaluateAuditWatches(auditStatus{enabled: 1}, selectOwn(), targets); !r.Error || r.Passed {
		t.Fatal("actual never action lost", r)
	}
	t.Log("AUDIT_NATIVE_PRIVATE_BOUNDARIES missing=fail attribute_missing=fail never=error cleanup=required")
}
