package windowsupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

func fixturePayload() Payload {
	return Payload{Contract: 1, HostIdentity: strings.Repeat("a", 64), Deadline: time.Now().Add(10 * time.Minute).UnixMilli(), Update: Update{ID: "12345678-1234-1234-1234-123456789abc", Revision: 7, Title: "Security update fixture", KB: []string{"1234567"}, Size: 1024, Eula: strings.Repeat("b", 64), Eligible: true}}
}
func encoded(p Payload) string { b, _ := json.Marshal(p); return string(b) }

type fakeWUA struct {
	calls                      []string
	reboot, afterBoot, unknown bool
	fail                       string
	mutate                     bool
}

func (f *fakeWUA) run(_ context.Context, r Request) (response, error) {
	f.calls = append(f.calls, r.Operation)
	if f.fail == r.Operation {
		return response{}, fmt.Errorf("native unavailable")
	}
	o := outcome(Payload{HostIdentity: r.HostIdentity, Update: r.Update}, "", "")
	o.BootID = "boot1"
	if f.afterBoot {
		o.BootID = "boot2"
	}
	switch r.Operation {
	case "download":
		o.Phase = "downloaded"
	case "install":
		o.Phase = "installed"
		o.ResultCode = 2
		o.RebootRequired = f.reboot
	case "verify":
		o.Installed = !f.unknown
		o.RebootRequired = f.reboot && !f.afterBoot
	}
	if f.mutate {
		o.Revision++
	}
	return response{Outcome: o}, nil
}
func TestPinnedInstallVerifiedAndDurableReplay(t *testing.T) {
	root := t.TempDir()
	p := fixturePayload()
	f := &fakeWUA{}
	r := repairWith("11", "22", encoded(p), root, f.run)
	if !r.Success || !r.Verified || r.RebootRequired || strings.Join(f.calls, ",") != "download,install,verify" {
		t.Fatalf("result=%+v calls=%v", r, f.calls)
	}
	// Losing the terminal stream report must still allow replay from disk.
	reports := reconcileWith(root, f.run)
	if len(reports) != 1 || !reports[0].Results[0].Verified {
		t.Fatal(reports)
	}
	Receipt(root, []string{"11-22-" + hashEvidence(r.ExecutionEvidence)})
	if len(reconcileWith(root, f.run)) != 0 {
		t.Fatal("committed outcome replayed after receipt")
	}
	p.Deadline = time.Now().Add(20 * time.Minute).UnixMilli()
	again := repairWith("11", "22", encoded(p), root, f.run)
	if again.ExecutionEvidence != r.ExecutionEvidence || len(f.calls) != 3 {
		t.Fatal("same task reinstalled")
	}
	p.Update.Revision++
	if repairWith("11", "22", encoded(p), root, f.run).Success || len(f.calls) != 3 {
		t.Fatal("changed target replayed")
	}
}
func TestRebootResultStaysUnverifiedUntilNativeRecheck(t *testing.T) {
	root := t.TempDir()
	p := fixturePayload()
	f := &fakeWUA{reboot: true}
	r := repairWith("12", "23", encoded(p), root, f.run)
	if !r.Success || r.Verified || !r.RebootRequired {
		t.Fatal(r)
	}
	// Even if SystemInfo clears early, the install's reboot requirement is durable.
	f.reboot = false
	reports := reconcileWith(root, f.run)
	if len(reports) != 1 || reports[0].Results[0].Verified || !reports[0].Results[0].RebootRequired {
		t.Fatal(reports)
	}
	f.afterBoot = true
	reports = reconcileWith(root, f.run)
	if len(reports) != 1 || !reports[0].Results[0].Verified {
		t.Fatal(reports)
	}
	for _, op := range f.calls[3:] {
		if op != "verify" {
			t.Fatal("recovery installed", f.calls)
		}
	}
}
func TestInstallInterruptionOnlyQueriesOnRecovery(t *testing.T) {
	root := t.TempDir()
	p := fixturePayload()
	f := &fakeWUA{fail: "install", unknown: true}
	if repairWith("13", "24", encoded(p), root, f.run).Success {
		t.Fatal("interrupted install succeeded")
	}
	f.fail = ""
	f.unknown = false
	reports := reconcileWith(root, f.run)
	if len(reports) != 1 || reports[0].Results[0].Verified || !reports[0].Results[0].RebootRequired || strings.Join(f.calls, ",") != "download,install,verify" {
		t.Fatalf("reports=%v calls=%v", reports, f.calls)
	}
	f.afterBoot = true
	if reports = reconcileWith(root, f.run); len(reports) != 1 || !reports[0].Results[0].Verified {
		t.Fatal(reports)
	}
}
func TestUncertainIntentSurvivesMissingTerminalWrite(t *testing.T) {
	root := t.TempDir()
	p := fixturePayload()
	dir := filepath.Join(root, "windows-updates")
	if err := securestate.PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := securestate.WriteJSON(filepath.Join(dir, "14-25.json"), record{Task: "14", Ref: "25", Pin: pin(p), Payload: p, Phase: "intent"}); err != nil {
		t.Fatal(err)
	}
	f := &fakeWUA{unknown: true}
	r := repairWith("14", "25", encoded(p), root, f.run)
	if r.Success || strings.Join(f.calls, ",") != "verify" {
		t.Fatal(r, f.calls)
	}
}
func TestInvalidExpiredAndChangedTargetsNeverInstall(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(*Payload)
		mutate bool
	}{
		{name: "expired", edit: func(p *Payload) { p.Deadline = 1 }},
		{name: "unknown_contract", edit: func(p *Payload) { p.Contract = 0 }},
		{name: "interactive", edit: func(p *Payload) { p.Update.Eligible = false; p.Update.Reason = "interactive_or_source_required" }},
		{name: "oversize_eligible", edit: func(p *Payload) { p.Update.Size = 5 << 30 }},
		{name: "query_injection", edit: func(p *Payload) { p.Update.ID = "x' or IsInstalled=0" }},
		{name: "changed_revision", edit: func(p *Payload) {}, mutate: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := fixturePayload()
			test.edit(&p)
			f := &fakeWUA{mutate: test.mutate}
			r := repairWith("15", "26", encoded(p), t.TempDir(), f.run)
			if r.Success {
				t.Fatal(r)
			}
			for _, op := range f.calls {
				if op == "install" {
					t.Fatal(f.calls)
				}
			}
		})
	}
}

func TestIneligibleLargeUpdateRemainsVisibleButCannotInstall(t *testing.T) {
	p := fixturePayload()
	p.Update.Size = 5 << 30
	p.Update.Title = strings.Repeat("安全", 200)
	p.Update.Eligible = false
	p.Update.Reason = "download_size_limit"
	if !validUpdate(p.Update) {
		t.Fatal("ineligible discovery metadata rejected")
	}
	f := &fakeWUA{}
	if repairWith("20", "30", encoded(p), t.TempDir(), f.run).Success || len(f.calls) != 0 {
		t.Fatal("ineligible update reached native execution")
	}
}
func TestCorruptAndFullRecoveryStateFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "windows-updates")
	if err := securestate.PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "16-27.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeWUA{}
	p := fixturePayload()
	if repairWith("16", "27", encoded(p), root, f.run).Success || len(f.calls) > 0 {
		t.Fatal("corrupt state accepted")
	}
	for i := 0; i < maxRecords; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("archived-%d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if repairWith("17", "28", encoded(p), root, f.run).Success || len(f.calls) > 0 {
		t.Fatal("capacity overflow accepted")
	}
}

func TestManualClosureStopsOnlyRecoveryQueries(t *testing.T) {
	root := t.TempDir()
	p := fixturePayload()
	f := &fakeWUA{reboot: true}
	if r := repairWith("19", "29", encoded(p), root, f.run); !r.RebootRequired {
		t.Fatal(r)
	}
	Receipt(root, []string{"19-29-closed"})
	if reports := reconcileWith(root, f.run); len(reports) != 0 || len(f.calls) != 3 {
		t.Fatal(reports, f.calls)
	}
	_ = repairWith("19", "29", encoded(p), root, f.run)
	if len(f.calls) != 3 {
		t.Fatal("closed target reinstalled")
	}
}
