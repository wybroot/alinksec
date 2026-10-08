//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNativeAPTSourcesPolicy(t *testing.T) {
	if os.Getenv("ALINKSEC_APT_NATIVE_REQUIRED") != "true" {
		t.Skip("disposable exact APT container only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-apt-fixture")
	status, statusErr := os.ReadFile("/proc/self/status")
	if _, e := os.Stat("/.dockerenv"); e != nil || err != nil || string(marker) != "isolated-apt-install-policy-v1\n" || statusErr != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000\n") || os.Geteuid() != 0 {
		t.Fatal("isolated cap0 root Docker required")
	}
	vendorSpec := aptSourcesSpec()
	vendorSpec.TimeoutMs = 5000
	if r := checkAPTSources(vendorSpec); r.Error || !r.Passed {
		t.Fatalf("vendor source declarations: %+v", r)
	} else {
		t.Logf("vendor source disk declaration, actual key/signature trust unverified: %s", r.Actual)
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/apt-sources/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Items) != 1 {
		t.Fatalf("source candidate: %v", err)
	}
	cs, err := ParseCheck(string(doc.Items[0].Check))
	if err != nil {
		t.Fatal(err)
	}
	report := Run("native-source-declarations", []*pb.BaselineCheckSpec{{ItemId: "source-item", Check: string(doc.Items[0].Check)}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(report.Items) != 1 || report.Items[0].ItemId != "source-item" || report.Items[0].ExecutionStatus != "pass" {
		t.Fatalf("actual dispatcher lost source evidence: %+v", report)
	}

	comparisons := 0
	for _, c := range aptSourceCases() {
		t.Run(c.name, func(t *testing.T) {
			root := aptSourcesFixture(t, c)
			for _, binary := range []string{"apt", "apt-get"} {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "/usr/local/bin/alinksec-apt-sources-oracle", root, binary)
				cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
				out, err := cmd.Output()
				if c.nativeError {
					if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 1 || !strings.Contains(string(e.Stderr), "Conflicting values") {
						t.Fatalf("native must reject semantic conflict: err=%v out=%q", err, out)
					}
					continue
				}
				if err != nil {
					t.Fatalf("native source parser: %v", err)
				}
				got := []string{}
				if strings.TrimSpace(string(out)) != "" {
					got = strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
				}
				want := slices.Clone(c.native)
				if c.name == "binary-get-insecure" && binary == "apt-get" {
					want[0] = strings.TrimSuffix(want[0], "false\tfalse\tfalse") + "true\tfalse\tfalse"
				}
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Fatalf("native %s fields got %#v want %#v", binary, got, want)
				}
				t.Logf("native %s parsed release declarations: %s", binary, strings.ReplaceAll(string(out), "\n", "; "))
				comparisons++
			}
			r := aptPolicyWithin(cs, root, aptPackage)
			if r.Error != c.candidateError || r.Passed != c.passed {
				t.Fatalf("native/candidate mismatch: %+v", r)
			}
		})
	}
	t.Logf("Native APT source declarations: cases=%d comparisons=%d skipped=0; inert non-key bytes accepted by metadata contract; key identity/material/repository signatures unverified", len(aptSourceCases()), comparisons)
}
