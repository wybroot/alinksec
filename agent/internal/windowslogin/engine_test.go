package windowslogin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
)

func sampleXML(id int, at time.Time, event, typ int, ip, user string) string {
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="%s" Guid="%s"/><EventID>%d</EventID><TimeCreated SystemTime="%s"/><EventRecordID>%d</EventRecordID><Channel>Security</Channel><Computer>win-host</Computer></System><EventData><Data Name="LogonType">%d</Data><Data Name="IpAddress">%s</Data><Data Name="TargetUserName">%s</Data><Data Name="TargetDomainName">LAB</Data><Data Name="Status">0xc000006d</Data><Data Name="SubStatus">0xc000006a</Data></EventData></Event>`, provider, providerGUID, event, at.Format(time.RFC3339Nano), id, typ, ip, user)
}
func TestXMLFieldIdentityAndRemoteScope(t *testing.T) {
	at := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	for _, tc := range []struct {
		name, ip string
		typ      int
		want     bool
	}{{"network", "192.0.2.4", 3, true}, {"remote", "2001:db8::4", 10, true}, {"mapped", "::ffff:192.0.2.4", 10, true}, {"local", "127.0.0.1", 3, false}, {"v6local", "::1", 10, false}, {"missing", "-", 3, false}, {"interactive", "192.0.2.4", 2, false}, {"service", "192.0.2.4", 5, false}, {"linklocal", "fe80::4", 3, false}} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Parse([]byte(sampleXML(4, at, 4625, tc.typ, tc.ip, "用户")))
			if err != nil || r.ID != 4 || r.Time != at || !hexSize(r.Fingerprint, 64) || (r.Attempt != nil) != tc.want {
				t.Fatalf("record=%+v err=%v", r, err)
			}
			if tc.want && (r.Attempt.Account != "LAB\\用户" || !r.Attempt.Failed) {
				t.Fatal(r.Attempt)
			}
		})
	}
	original := sampleXML(4, at, 4625, 3, "192.0.2.4", "user")
	for _, bad := range []string{strings.Replace(original, "<EventID>4625</EventID>", "<EventID>4625</EventID><EventID>4624</EventID>", 1), strings.Replace(original, "</EventData>", `<Data Name="IpAddress">198.51.100.8</Data></EventData>`, 1), original + original, strings.Replace(original, "2026-10-18", "invalid", 1), strings.Repeat(" ", maxXML+1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("accepted ambiguous/malformed event")
		}
	}
	wrong := strings.Replace(original, provider, "Fake-Provider", 1)
	r, err := Parse([]byte(wrong))
	if err != nil || r.Attempt != nil {
		t.Fatal("accepted spoofed provider")
	}
}

type fakeReader struct {
	records          []Record
	err              error
	success, failure bool
}

func (f *fakeReader) Latest() (Record, error) {
	if f.err != nil {
		return Record{}, f.err
	}
	if len(f.records) == 0 {
		return Record{}, nil
	}
	return f.records[len(f.records)-1], nil
}
func (f *fakeReader) Find(id uint64) (Record, error) {
	for _, r := range f.records {
		if r.ID == id {
			return r, f.err
		}
	}
	return Record{}, f.err
}
func (f *fakeReader) After(id, upper uint64, limit int) ([]Record, error) {
	var out []Record
	for _, r := range f.records {
		if r.ID > id && r.ID <= upper && r.Attempt != nil {
			out = append(out, r)
			if len(out) == limit {
				break
			}
		}
	}
	return out, f.err
}
func (f *fakeReader) Audit() (bool, bool, error) { return f.success, f.failure, f.err }
func (f *fakeReader) add(t *testing.T, at time.Time, id, event, typ int, ip, user string) {
	t.Helper()
	r, err := Parse([]byte(sampleXML(id, at, event, typ, ip, user)))
	if err != nil {
		t.Fatal(err)
	}
	f.records = append(f.records, r)
}

type fakeFirewall struct {
	blocks  map[string]Block
	err     error
	applies int
}

func (f *fakeFirewall) Apply(b Block) error {
	if f.err != nil {
		return f.err
	}
	f.blocks[b.Key] = b
	f.applies++
	return nil
}
func (f *fakeFirewall) Remove(k string) error { delete(f.blocks, k); return nil }
func (f *fakeFirewall) Close() error          { clear(f.blocks); return nil }
func (f *fakeFirewall) Active() (int, bool)   { return len(f.blocks), false }
func testRule() config.LoginRule {
	return config.LoginRule{ID: "PR-0004", Name: "Windows 登录防护", Enabled: true, Severity: 4, Actions: []string{"alert", "block_ip"}, Match: config.LoginMatch{WindowsContract: 1, Platforms: []string{"windows"}, WindowsPorts: []int{3389}, WindowsLogonTypes: []int{3, 10}, FailureThreshold: 2, WindowSec: 60, CooldownSec: 10, BlockDurationSec: 30, Timezone: "UTC"}}
}
func fixture(t *testing.T) (*Engine, *fakeReader, *fakeFirewall, *time.Time) {
	t.Helper()
	at := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	r := &fakeReader{success: true, failure: true}
	f := &fakeFirewall{blocks: map[string]Block{}}
	r.add(t, at.Add(-time.Second), 1, 4625, 10, "192.0.2.8", "old")
	e := newEngine(t.TempDir(), "203.0.113.10:8443", slog.New(slog.NewTextHandler(io.Discard, nil)), r, f)
	e.now = func() time.Time { return at }
	e.Update([]config.LoginRule{testRule()})
	e.Poll()
	return e, r, f, &at
}
func addFailures(t *testing.T, r *fakeReader, at time.Time, start int, ip string) {
	r.add(t, at, start, 4625, 10, ip, "user")
	r.add(t, at, start+1, 4625, 10, ip, "other")
}
func TestCursorCountersReceiptAndRestart(t *testing.T) {
	e, r, f, at := fixture(t)
	if len(e.Events()) != 0 || e.s.Cursor != 1 {
		t.Fatal("startup replay")
	}
	addFailures(t, r, *at, 2, "192.0.2.8")
	e.Poll()
	events := e.Events()
	if len(events) != 1 || events[0].Action != "blocked_ip" || len(f.blocks) != 1 {
		t.Fatalf("events=%+v blocks=%v status=%+v", events, f.blocks, e.Status())
	}
	e.Poll()
	if len(e.Events()) != 1 || f.applies != 1 {
		t.Fatal("duplicate caused response")
	}
	restartedFW := &fakeFirewall{blocks: map[string]Block{}}
	restarted := newEngine(filepath.Dir(e.path), e.server, e.log, r, restartedFW)
	restarted.now = e.now
	restarted.Update([]config.LoginRule{testRule()})
	restarted.Poll()
	if len(restarted.Events()) != 1 || restarted.Events()[0].ID != events[0].ID || len(restartedFW.blocks) != 1 {
		t.Fatal("restart lost cursor/event/block")
	}
	for _, b := range restartedFW.blocks {
		if b.Expires != at.Add(30*time.Second).UnixMilli() {
			t.Fatal("restart extended expiry")
		}
	}
	if err := restarted.Receipt([]string{events[0].ID}); err != nil {
		t.Fatal(err)
	}
	again := newEngine(filepath.Dir(e.path), e.server, e.log, r, &fakeFirewall{blocks: map[string]Block{}})
	if len(again.Events()) != 0 {
		t.Fatal("ack not durable")
	}
	*at = at.Add(31 * time.Second)
	restarted.Poll()
	if len(restartedFW.blocks) != 0 {
		t.Fatal("expiry")
	}
}
func TestPersistenceFailureCannotAdvanceOrInstall(t *testing.T) {
	e, r, f, at := fixture(t)
	addFailures(t, r, *at, 2, "192.0.2.8")
	write := e.write
	e.write = func(string, any, int) error { return errors.New("disk full") }
	e.Poll()
	if e.s.Cursor != 1 || len(f.blocks) != 0 || len(e.Events()) != 0 || e.Status().Issue != "persist_failed" {
		t.Fatal(e.Status())
	}
	e.write = write
	e.Poll()
	if len(e.Events()) != 1 || len(f.blocks) != 1 {
		t.Fatal("retry lost event")
	}
	before := e.Events()[0].ID
	e.write = func(string, any, int) error { return errors.New("disk full") }
	if e.Receipt([]string{before}) == nil || len(e.Events()) != 1 {
		t.Fatal("failed receipt lost journal")
	}
}
func TestCrashAfterInstallBeforeOutcomeCommit(t *testing.T) {
	e, r, f, at := fixture(t)
	addFailures(t, r, *at, 2, "192.0.2.8")
	write := e.write
	writes := 0
	e.write = func(p string, v any, n int) error {
		writes++
		if writes == 2 {
			return errors.New("outcome write failed")
		}
		return write(p, v, n)
	}
	e.Poll()
	if len(f.blocks) != 1 || len(e.Events()) != 0 || e.Status().Issue != "persist_failed" {
		t.Fatalf("%+v %+v", e.Status(), e.Events())
	}
	fw := &fakeFirewall{blocks: map[string]Block{}}
	again := newEngine(filepath.Dir(e.path), e.server, e.log, r, fw)
	again.now = e.now
	again.Update([]config.LoginRule{testRule()})
	again.Poll()
	if len(again.Events()) != 1 || again.Events()[0].Action != "blocked_ip" || len(fw.blocks) != 1 {
		t.Fatal("unresolved durable intent")
	}
}
func TestLogClearAndRecordReuseStartNewGeneration(t *testing.T) {
	e, r, _, at := fixture(t)
	r.add(t, *at, 2, 4625, 10, "192.0.2.8", "one")
	e.Poll()
	gen := e.s.Generation
	r.records = nil
	r.add(t, at.Add(time.Second), 2, 4625, 10, "192.0.2.8", "reused")
	*at = at.Add(time.Second)
	e.Poll()
	if e.s.Generation == gen || len(e.s.Buckets) != 0 || e.Status().Issue != "log_gap" {
		t.Fatal(e.Status())
	}
	r.add(t, *at, 3, 4625, 10, "192.0.2.8", "one")
	e.Poll()
	if len(e.Events()) != 0 {
		t.Fatal("count crossed log generation")
	}
}
func TestExclusionsScopeOffHoursAndWithdrawal(t *testing.T) {
	e, r, f, at := fixture(t)
	rule := testRule()
	rule.Match.TrustedIPs = []string{"192.0.2.0/24"}
	rule.Match.UserExclude = []string{"lab\\BACKUP"}
	e.Update([]config.LoginRule{rule})
	addFailures(t, r, *at, 2, "192.0.2.8")
	r.add(t, *at, 4, 4625, 10, "198.51.100.8", "backup")
	r.add(t, *at, 5, 4625, 10, "198.51.100.8", "backup")
	e.Poll()
	if len(e.Events()) != 0 {
		t.Fatal("exclusion")
	}
	rule.Match.OffHoursEnabled = true
	rule.Match.AllowedStartHour = 8
	rule.Match.AllowedEndHour = 20
	e.Update([]config.LoginRule{rule})
	r.add(t, *at, 6, 4624, 3, "198.51.100.8", "user")
	e.Poll()
	if len(e.Events()) != 1 || e.Events()[0].Type != "login_anomaly" || len(f.blocks) != 0 {
		t.Fatal("off-hours success blocked")
	}
	addFailures(t, r, *at, 7, "198.51.100.8")
	e.Poll()
	if len(f.blocks) != 1 {
		t.Fatal("missing block")
	}
	rule.Match.TrustedIPs = append(rule.Match.TrustedIPs, "198.51.100.8")
	e.Update([]config.LoginRule{rule})
	if len(f.blocks) != 0 {
		t.Fatal("trusted change did not withdraw")
	}
}
func TestManagementAndFirewallFailureRemainVisible(t *testing.T) {
	for _, which := range []string{"management", "firewall"} {
		t.Run(which, func(t *testing.T) {
			e, r, f, at := fixture(t)
			ip := "192.0.2.8"
			if which == "management" {
				ip = "203.0.113.10"
			} else {
				f.err = errors.New("WFP denied")
			}
			addFailures(t, r, *at, 2, ip)
			e.Poll()
			if len(e.Events()) != 1 || e.Events()[0].Action != "block_failed" || len(f.blocks) != 0 || e.Status().Issue != "block_failed" {
				t.Fatal(e.Status(), e.Events())
			}
		})
	}
}
func TestUnacknowledgedJournalBackpressureAndRecovery(t *testing.T) {
	e, r, _, at := fixture(t)
	rule := testRule()
	rule.Actions = []string{"alert"}
	e.Update([]config.LoginRule{rule})
	// Each source crosses the threshold independently in one bounded batch.
	for i := 0; i < 64; i++ {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}).String()
		addFailures(t, r, *at, 2+i*2, ip)
	}
	e.Poll()
	if len(e.Events()) != 64 {
		t.Fatal(len(e.Events()))
	}
	cursor := e.s.Cursor
	addFailures(t, r, *at, 130, "203.0.113.8")
	e.Poll()
	if e.s.Cursor != cursor+1 || e.Status().Issue != "event_buffer_full" {
		t.Fatal(e.Status())
	}
	ids := []string{}
	for _, v := range e.Events() {
		ids = append(ids, v.ID)
	}
	if err := e.Receipt(ids); err != nil {
		t.Fatal(err)
	}
	e.Poll()
	if len(e.Events()) != 1 || e.s.Cursor != 131 {
		t.Fatal(e.Status())
	}
}
func TestAuditAndJournalFailuresCannotLookHealthy(t *testing.T) {
	e, r, _, _ := fixture(t)
	r.failure = false
	e.Poll()
	if e.Status().Issue != "audit_disabled" {
		t.Fatal(e.Status())
	}
	r.err = errors.New("denied")
	e.Poll()
	if e.Status().Issue != "audit_query_failed" {
		t.Fatal(e.Status())
	}
	if err := os.WriteFile(e.path, []byte(`{"version":99}`), 0600); err != nil {
		t.Fatal(err)
	}
	again := newEngine(filepath.Dir(e.path), e.server, e.log, r, &fakeFirewall{blocks: map[string]Block{}})
	again.Update([]config.LoginRule{testRule()})
	again.Poll()
	if again.Status().Issue != "journal_invalid" {
		t.Fatal(again.Status())
	}
}
func TestPolicyOptInAndTypeFilter(t *testing.T) {
	e, r, f, at := fixture(t)
	rule := testRule()
	rule.Match.WindowsContract = 0
	e.Update([]config.LoginRule{rule})
	addFailures(t, r, *at, 2, "192.0.2.8")
	e.Poll()
	if e.Status().State != "disabled" || len(f.blocks) != 0 {
		t.Fatal(e.Status())
	}
	rule = testRule()
	rule.Match.WindowsLogonTypes = []int{10}
	e.Update([]config.LoginRule{rule})
	e.Poll()
	r.add(t, *at, 4, 4625, 3, "192.0.2.8", "one")
	r.add(t, *at, 5, 4625, 3, "192.0.2.8", "two")
	e.Poll()
	if len(e.Events()) != 0 {
		t.Fatal("type filter")
	}
	if slices.Contains(rule.Match.Platforms, "linux") {
		t.Fatal("scope")
	}
	var status map[string]any
	if json.Unmarshal([]byte(e.StatusJSON()), &status) != nil {
		t.Fatal("status JSON")
	}
}

func TestFullSuccessBatchCanDrainInMultipleReceiptedSegments(t *testing.T) {
	e, r, _, at := fixture(t)
	rule := testRule()
	rule.Match.OffHoursEnabled = true
	rule.Match.AllowedStartHour = 8
	rule.Match.AllowedEndHour = 20
	e.Update([]config.LoginRule{rule})
	for i := 0; i < 128; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		r.add(t, *at, i+2, 4624, 3, ip, "user")
	}
	e.Poll()
	if len(e.Events()) != 64 || e.s.Cursor != 65 || e.Status().Issue != "event_buffer_full" {
		t.Fatal(e.Status(), len(e.Events()))
	}
	ids := []string{}
	for _, v := range e.Events() {
		ids = append(ids, v.ID)
	}
	if err := e.Receipt(ids); err != nil {
		t.Fatal(err)
	}
	e.Poll()
	if len(e.Events()) != 64 || e.s.Cursor != 129 {
		t.Fatal(e.Status(), len(e.Events()))
	}
}
func TestPolicyWithdrawalStillRemovesFiltersWhenDiskFails(t *testing.T) {
	e, r, f, at := fixture(t)
	addFailures(t, r, *at, 2, "192.0.2.8")
	e.Poll()
	if len(f.blocks) != 1 {
		t.Fatal("fixture")
	}
	e.write = func(string, any, int) error { return errors.New("disk full") }
	e.Update(nil)
	if len(f.blocks) != 0 || e.Status().Issue != "persist_failed" {
		t.Fatal(e.Status())
	}
}

func TestClockRollbackWithdrawsInsteadOfExtendingPersistedBlock(t *testing.T) {
	e, r, f, at := fixture(t)
	addFailures(t, r, *at, 2, "192.0.2.8")
	e.Poll()
	if len(f.blocks) != 1 {
		t.Fatal("fixture")
	}
	*at = at.Add(-time.Second)
	fw := &fakeFirewall{blocks: map[string]Block{}}
	again := newEngine(filepath.Dir(e.path), e.server, e.log, r, fw)
	again.now = e.now
	again.Update([]config.LoginRule{testRule()})
	if len(fw.blocks) != 0 || len(again.s.Blocks) != 0 {
		t.Fatal("clock rollback extended block")
	}
}
