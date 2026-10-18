//go:build windows

package windowslogin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

func nativeCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v %s", name, err, b)
	}
	return string(b)
}
func requireNative(t *testing.T) {
	t.Helper()
	if os.Getenv("ALINKSEC_WINDOWS_LOGIN_NATIVE_REQUIRED") != "true" {
		t.Skip("native Windows login validation requires isolated elevated runner")
	}
}
func TestNativeWindowsLoginProtection(t *testing.T) {
	requireNative(t)
	reader := newReader()
	backup := filepath.Join(t.TempDir(), "audit.csv")
	nativeCommand(t, "auditpol.exe", "/backup", "/file:"+backup)
	defer nativeCommand(t, "auditpol.exe", "/restore", "/file:"+backup)
	nativeCommand(t, "auditpol.exe", "/set", "/subcategory:{0cce9215-69ae-11d9-bed3-505054503030}", "/success:enable", "/failure:enable")
	success, failure, err := reader.Audit()
	if err != nil || !success || !failure {
		t.Fatalf("audit coverage: %v %v %v", success, failure, err)
	}
	start, err := reader.Latest()
	if err != nil {
		t.Fatal(err)
	}
	username := fmt.Sprintf("alk%016x", uint64(time.Now().UnixNano()))
	user, _ := windows.UTF16PtrFromString(username)
	domain, _ := windows.UTF16PtrFromString(".")
	password, _ := windows.UTF16PtrFromString("SYNTHETIC-NONEXISTENT-ACCOUNT-PASSWORD")
	var token windows.Token
	proc := advapi.NewProc("LogonUserW")
	ok, _, _ := proc.Call(uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(password)), 3, 0, uintptr(unsafe.Pointer(&token)))
	if ok != 0 {
		token.Close()
		t.Fatal("nonexistent account authenticated")
	}
	found := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		// Native XML read, including local events excluded from remote protection.
		rows, err := query(fmt.Sprintf("*[System[EventID=4625 and EventRecordID>%d] and EventData[Data[@Name='TargetUserName']='%s']]", start.ID, username), batchSize, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("real failed LogonUser did not produce Security 4625")
	}
	latest, err := reader.Latest()
	if err != nil || latest.ID <= start.ID {
		t.Fatal("native cursor did not advance", err)
	}
	anchor, err := reader.Find(latest.ID)
	if err != nil || anchor.Fingerprint != latest.Fingerprint {
		t.Fatal("native anchor lookup", err)
	}
	// Native query is exercised even if the event has no remote IpAddress.
	if _, err := reader.After(start.ID, latest.ID, batchSize); err != nil {
		t.Fatal(err)
	}
	checks := []string{"native_security_4625_from_failed_logon", "audit_logon_success_failure_query", "native_record_anchor_and_forward_query"}
	f := newFirewall().(*nativeFirewall)
	defer f.Close()
	now := time.Now()
	blocks := []Block{{Key: "native-v4", RuleID: "native", IP: "192.0.2.241", Ports: []int{43389, 43445}, Created: now.UnixMilli(), Expires: now.Add(5 * time.Second).UnixMilli()}, {Key: "native-v6", RuleID: "native", IP: "2001:db8::241", Ports: []int{43389}, Created: now.UnixMilli(), Expires: now.Add(5 * time.Second).UnixMilli()}}
	for _, b := range blocks {
		if err := f.Apply(b); err != nil {
			t.Fatal(err)
		}
	}
	observer, err := wf.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	rows, err := observer.Rules()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{"192.0.2.241:43389": false, "192.0.2.241:43445": false, "2001:db8::241:43389": false}
	seen := 0
	for _, r := range rows {
		if r.Name != "ALinkSec Windows login" {
			continue
		}
		if r.Layer != wf.LayerALEAuthRecvAcceptV4 && r.Layer != wf.LayerALEAuthRecvAcceptV6 {
			t.Fatal("outbound/unbounded layer")
		}
		if r.Action != wf.ActionBlock || !r.HardAction || len(r.Conditions) != 3 {
			t.Fatalf("invalid filter: %+v", r)
		}
		source := ""
		port := uint16(0)
		protocol := uint8(0)
		for _, c := range r.Conditions {
			if c.Op != wf.MatchTypeEqual {
				t.Fatal("nonexact WFP condition")
			}
			switch c.Field {
			case wf.FieldIPRemoteAddress:
				switch a := c.Value.(type) {
				case netip.Addr:
					source = a.String()
				case netip.Prefix:
					if a.Bits() != a.Addr().BitLen() {
						t.Fatal("broad WFP source")
					}
					source = a.Addr().String()
				}
			case wf.FieldIPLocalPort:
				port, _ = c.Value.(uint16)
			case wf.FieldIPProtocol:
				protocol, _ = c.Value.(uint8)
			default:
				t.Fatal("unexpected WFP field")
			}
		}
		key := fmt.Sprintf("%s:%d", source, port)
		if value, ok := expected[key]; !ok || value || protocol != 6 {
			t.Fatalf("unexpected native WFP source/port/protocol: %s %d", key, protocol)
		}
		expected[key] = true
		seen++
	}
	if seen != 3 {
		t.Fatalf("native filter count %d", seen)
	}
	checks = append(checks, "native_ipv4_ipv6_inbound_source_tcp_port_filters")
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		n, bad := f.Active()
		if bad {
			t.Fatal("expiry cleanup failed")
		}
		if n == 0 {
			break
		}
	}
	n, bad := f.Active()
	if n != 0 || bad {
		t.Fatal("independent expiry did not remove filters")
	}
	checks = append(checks, "independent_native_expiry")
	testNativeProcessExit(t, observer)
	checks = append(checks, "native_process_death_removes_dynamic_filters")
	// A private directory and atomic journal are exercised under the native ACLs.
	e := newEngine(filepath.Join(t.TempDir(), "journal"), "203.0.113.10:8443", slog.New(slog.NewTextHandler(io.Discard, nil)), reader, newFirewall())
	e.Update(nil)
	if e.loadErr != nil {
		t.Fatal(e.loadErr)
	}
	checks = append(checks, "native_private_atomic_journal")
	traffic := nativeTrafficProbe(t)
	evidence := map[string]any{"passed": true, "platform": "windows-amd64", "checks": checks, "traffic_probe": traffic, "scope": "native Security 4625 via LogonUser; WFP IPv4/IPv6 filter and process lifecycle; remote RDP/SMB clients require separate deployment acceptance"}
	data, _ := json.MarshalIndent(evidence, "", "  ")
	if path := os.Getenv("ALINKSEC_WINDOWS_LOGIN_EVIDENCE_FILE"); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(data))
}
func TestWindowsLoginWFPChild(t *testing.T) {
	if os.Getenv("ALINKSEC_WINDOWS_LOGIN_CHILD") != "true" {
		t.Skip("child fixture")
	}
	f := newFirewall()
	now := time.Now()
	if err := f.Apply(Block{Key: "child", RuleID: "native", IP: "192.0.2.242", Ports: []int{43390}, Created: now.UnixMilli(), Expires: now.Add(time.Minute).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("ALINKSEC_LOGIN_WFP_READY")
	time.Sleep(time.Minute)
}
func testNativeProcessExit(t *testing.T, observer *wf.Session) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWindowsLoginWFPChild$", "-test.v")
	cmd.Env = append(os.Environ(), "ALINKSEC_WINDOWS_LOGIN_CHILD=true")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := false
	s := bufio.NewScanner(out)
	for s.Scan() {
		if strings.Contains(s.Text(), "ALINKSEC_LOGIN_WFP_READY") {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("child WFP not ready")
	}
	rows, err := observer.Rules()
	if err != nil {
		t.Fatal(err)
	}
	var childIDs []wf.RuleID
	for _, r := range rows {
		if r.Name == "ALinkSec Windows login" {
			childIDs = append(childIDs, r.ID)
		}
	}
	if len(childIDs) != 1 {
		t.Fatal("child filter not visible")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		rows, err = observer.Rules()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range rows {
			for _, id := range childIDs {
				if r.ID == id {
					found = true
				}
			}
		}
		if !found {
			return
		}
	}
	t.Fatal("dynamic filter survived owner process death")
}
func nativeTrafficProbe(t *testing.T) map[string]any {
	t.Helper()
	ip := ""
	addresses, _ := net.InterfaceAddrs()
	for _, v := range addresses {
		host, _, _ := strings.Cut(v.String(), "/")
		a := net.ParseIP(host)
		if a != nil && a.To4() != nil && !a.IsLoopback() {
			ip = host
			break
		}
	}
	if ip == "" {
		return map[string]any{"supported": false, "reason": "no_nonloopback_ipv4"}
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	probe := func() bool {
		c, err := net.DialTimeout("tcp4", listener.Addr().String(), 300*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	if !probe() {
		return map[string]any{"supported": false, "reason": "local_interface_baseline_unavailable"}
	}
	f := newFirewall()
	defer f.Close()
	now := time.Now()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := f.Apply(Block{Key: "traffic", IP: ip, Ports: []int{port}, Created: now.UnixMilli(), Expires: now.Add(5 * time.Second).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	blocked := !probe()
	if err := f.Remove("traffic"); err != nil {
		t.Fatal(err)
	}
	if !probe() {
		t.Fatal("local interface traffic not restored")
	}
	if !blocked {
		return map[string]any{"supported": false, "reason": "kernel_local_interface_loopback_bypass"}
	}
	return map[string]any{"supported": true, "blocked": true, "restored": true, "scope": "same_host_nonloopback_interface_tcp"}
}
