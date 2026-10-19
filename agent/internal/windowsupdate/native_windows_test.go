//go:build windows

package windowsupdate

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

//go:embed testdata/provider.ps1
var providerFixture string

func TestNativeWindowsUpdateWorker(t *testing.T) {
	if os.Getenv("ALINKSEC_WINDOWS_UPDATE_NATIVE_REQUIRED") != "true" {
		t.Skip("native WUA acceptance is explicitly enabled in CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	actual, err := nativeRun(ctx, Request{Operation: "probe", Deadline: time.Now().Add(time.Minute).UnixMilli()})
	if err != nil || actual.Snapshot.Status != "complete" || !digest.MatchString(actual.Snapshot.HostIdentity) {
		t.Fatalf("actual WUA interfaces/identity/quiet properties unavailable: %+v %v", actual, err)
	}
	results := map[string]any{"native_api_probe": actual.Snapshot, "scope": "actual WUA COM interfaces and quiet properties; controlled provider exercises production worker, no live system update installed"}
	for _, mode := range []string{"normal", "changed", "eula", "interactive", "pre_reboot", "absent", "download_partial", "install_partial", "install_reboot"} {
		t.Run(mode, func(t *testing.T) {
			var lines []string
			for _, line := range strings.Split(providerFixture+"\n"+worker, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					lines = append(lines, line)
				}
			}
			script := "$script:Mode='" + mode + "'\n" + strings.Join(lines, "\n")
			run := func(ctx context.Context, r Request) (response, error) { return runScript(ctx, r, script) }
			scan, err := run(ctx, Request{Operation: "scan", Deadline: time.Now().Add(time.Minute).UnixMilli()})
			if err != nil || scan.Snapshot.Status != "complete" {
				t.Fatalf("controlled discovery failed: %v", err)
			}
			p := fixturePayload()
			p.HostIdentity = actual.Snapshot.HostIdentity
			if len(scan.Snapshot.Updates) > 0 {
				p.Update = scan.Snapshot.Updates[0]
			}
			if mode == "changed" {
				p.Update.Revision = 7
			}
			r := repairWith("51", "61", encoded(p), t.TempDir(), run)
			if mode == "normal" {
				if !r.Success || !r.Verified {
					t.Fatalf("%+v", r)
				}
			} else if mode == "install_reboot" {
				if !r.Success || r.Verified || !r.RebootRequired {
					t.Fatalf("%+v", r)
				}
			} else if r.Success {
				t.Fatalf("unsafe update succeeded: %+v", r)
			}
			results[mode] = r
		})
	}
	if t.Failed() {
		return
	}
	path := os.Getenv("ALINKSEC_WINDOWS_UPDATE_EVIDENCE_FILE")
	if path == "" {
		t.Fatal("missing native evidence path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
