//go:build windows

package windowslogin

import (
	"encoding/json"
	"fmt"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/windows"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestNativeWindowsRawLogs(t *testing.T) {
	requireNative(t)
	reader := newReader()
	backup := filepath.Join(t.TempDir(), "audit.csv")
	nativeCommand(t, "auditpol.exe", "/backup", "/file:"+backup)
	defer nativeCommand(t, "auditpol.exe", "/restore", "/file:"+backup)
	nativeCommand(t, "auditpol.exe", "/set", "/subcategory:{0cce9215-69ae-11d9-bed3-505054503030}", "/success:enable", "/failure:enable")
	dir := filepath.Join(t.TempDir(), "journal")
	e := newEngine(dir, "example:443", slog.New(slog.NewTextHandler(io.Discard, nil)), reader, &fakeFirewall{})
	defer e.firewall.Close()
	username := fmt.Sprintf("raw%016x", uint64(time.Now().UnixNano()))
	var rejected, accepted *pb.LogLine
	allow := false
	sink := func(lines []*pb.LogLine) bool {
		for _, l := range lines {
			if strings.Contains(l.Content, username) {
				if !allow {
					rejected = l
					return false
				}
				accepted = l
			}
		}
		return true
	}
	e.SetRawSink(sink)
	e.Update(nil)
	e.Poll()
	baseline := e.s.Cursor
	user, _ := windows.UTF16PtrFromString(username)
	domain, _ := windows.UTF16PtrFromString(".")
	password, _ := windows.UTF16PtrFromString("SYNTHETIC-NONEXISTENT-ACCOUNT-PASSWORD")
	var token windows.Token
	ok, _, _ := advapi.NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(password)), 3, 0, uintptr(unsafe.Pointer(&token)))
	if ok != 0 {
		token.Close()
		t.Fatal("nonexistent account authenticated")
	}
	found := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		rows, err := query(fmt.Sprintf("*[System[EventID=4625 and EventRecordID>%d] and EventData[Data[@Name='TargetUserName']='%s']]", baseline, username), batchSize, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("native failed logon event did not appear")
	}
	e.Poll()
	if rejected == nil || e.s.Cursor != baseline || e.Status().Issue != "raw_log_queue_failed" {
		t.Fatal("native raw event missing or rejection cursor advanced")
	}
	allow = true
	e.Poll()
	if accepted == nil || accepted.Content != rejected.Content || accepted.Fields["source_event_id"] != rejected.Fields["source_event_id"] || accepted.Fields["event_id"] != "4625" {
		t.Fatal("native XML/retry changed")
	}
	parsed, err := Parse([]byte(accepted.Content))
	if err != nil || parsed.EventID != "4625" || parsed.ID == 0 {
		t.Fatal("not original native Security XML", err)
	}
	committed := e.s.Cursor
	acceptedKey := accepted.Fields["source_event_id"]
	replayed := false
	restart := newEngine(dir, "example:443", e.log, reader, &fakeFirewall{})
	defer restart.firewall.Close()
	restart.SetRawSink(func(lines []*pb.LogLine) bool {
		for _, l := range lines {
			if l.Fields["source_event_id"] == acceptedKey {
				replayed = true
			}
		}
		return true
	})
	restart.Update(nil)
	restart.Poll()
	if replayed || restart.s.Cursor < committed {
		t.Fatal("native restart repeated committed event")
	}
	evidence := map[string]any{"passed": true, "platform": "windows-amd64", "head": os.Getenv("GITHUB_SHA"), "checks": []string{"real_failed_LogonUser_4625", "native_Security_XML_preserved", "same_reader_cursor_without_protection_policy", "spool_refusal_keeps_cursor", "retry_keeps_source_event_identity", "private_cursor_restart_no_replay"}, "line": accepted}
	if out := os.Getenv("ALINKSEC_RAW_LOG_EVIDENCE_FILE"); out != "" {
		data, _ := json.MarshalIndent(evidence, "", "  ")
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
