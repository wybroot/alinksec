//go:build windows

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/isolation"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func prepareIsolationNative(t *testing.T, work, probeIP string) {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	if service, err := manager.OpenService("alinksec-agent-isolation-watchdog"); err == nil {
		service.Close()
		t.Fatal("refusing existing isolation watchdog service")
	} else if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(work))
	name := fmt.Sprintf("alinksec-native-isolation-%x", digest[:6])
	nativeIsolationCommand(t, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; New-NetFirewallRule -Name '"+name+"' -DisplayName '"+name+"' -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress '"+probeIP+"' -RemotePort 443 | Out-Null")
	t.Cleanup(func() {
		m, err := mgr.Connect()
		if err != nil {
			t.Error(err)
			return
		}
		defer m.Disconnect()
		if helper, err := m.OpenService("alinksec-agent-isolation-watchdog"); err == nil {
			defer helper.Close()
			cfg, e := helper.Config()
			if e != nil || !strings.Contains(cfg.BinaryPathName, work) {
				t.Error("unrelated isolation watchdog during cleanup")
				return
			}
			helper.Control(svc.Stop)
			awaitSCMState(t, helper, svc.Stopped)
			l, e := isolation.Current(work)
			if e == nil && l.Phase != "finished" {
				t.Error("cleanup still pending; preserve native recovery service")
				return
			}
			helper.ResetRecoveryActions()
			helper.Delete()
		}
		nativeIsolationCommand(t, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; Remove-NetFirewallRule -Name '"+name+"'")
	})
}
func isolationNativePolicy(t *testing.T) string {
	t.Helper()
	out := nativeIsolationCommand(t, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; Get-NetFirewallProfile | Sort-Object Name | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules | ConvertTo-Json -Compress; Get-NetFirewallRule -Name 'alinksec-native-isolation-*' | Sort-Object Name | Select-Object Name,Enabled,Direction,Action,Profile | ConvertTo-Json -Compress")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(out)))
}
func assertIsolationNativeRules(t *testing.T, l *isolation.Lease) {
	t.Helper()
	s, err := wf.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rules, err := s.Rules()
	if err != nil {
		t.Fatal(err)
	}
	want := map[wf.LayerID]bool{wf.LayerALEAuthConnectV4: false, wf.LayerALEAuthRecvAcceptV4: false, wf.LayerALEAuthConnectV6: false, wf.LayerALEAuthRecvAcceptV6: false}
	for _, r := range rules {
		if r.Name == "ALinkSec isolation "+l.ID && r.Action == wf.ActionBlock {
			want[r.Layer] = true
		}
	}
	for layer, found := range want {
		if !found {
			t.Fatalf("missing native dual-stack deny filter: %s", layer)
		}
	}
}
func crashIsolationNativeOwner(t *testing.T) {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService("alinksec-agent-isolation-watchdog")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := awaitSCMState(t, s, svc.Running)
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, st.ProcessId)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		t.Fatal(err)
	}
}
func waitIsolationNativeRemoved(t *testing.T) {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	for i := 0; i < 60; i++ {
		s, err := m.OpenService("alinksec-agent-isolation-watchdog")
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return
		}
		if s != nil {
			s.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("completed isolation watchdog service was not removed")
}
