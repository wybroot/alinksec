//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeAPTInstallPolicy(t *testing.T) {
	if os.Getenv("ALINKSEC_APT_NATIVE_REQUIRED") != "true" {
		t.Skip("disposable exact APT container only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-apt-fixture")
	status, statusErr := os.ReadFile("/proc/self/status")
	if _, e := os.Stat("/.dockerenv"); e != nil || err != nil || string(marker) != "isolated-apt-install-policy-v1\n" || statusErr != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000\n") || os.Geteuid() != 0 {
		t.Fatal("isolated root Docker fixture without capabilities required")
	}
	cs := aptSpec()
	cs.TimeoutMs = 5000
	if r := checkAPTPolicy(cs); r.Error || !r.Passed {
		t.Fatalf("vendor disk defaults: %+v", r)
	} else {
		t.Logf("vendor defaults, actual invocation/trust unverified: %s", r.Actual)
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/apt/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Items) != 1 {
		t.Fatalf("candidate: %v", err)
	}
	cs, err = ParseCheck(string(doc.Items[0].Check))
	if err != nil {
		t.Fatal(err)
	}
	comparisons := 0
	for _, c := range aptCases() {
		t.Run(c.name, func(t *testing.T) {
			root := aptFixture(t, c.main, c.parts)
			// APT_CONFIG is exclusively an oracle harness redirect in this disposable
			// container. Production rejects redirects and never calls an APT frontend.
			oracle := filepath.Join(root, "oracle.conf")
			if err := os.WriteFile(oracle, []byte("Dir::Etc \""+filepath.Join(root, "etc/apt")+"\";\n"), 0644); err != nil {
				t.Fatal(err)
			}
			wantByBinary := map[string][]bool{"apt": {c.aptU, c.aptF}, "apt-get": {c.getU, c.getF}}
			passed := true
			for _, binary := range []string{"apt", "apt-get"} {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				// argv[0] selects the REAL APT binary-specific overlay before CLI parsing.
				// Only the apt-config executable runs; output is parsed as data, no eval.
				cmd := exec.CommandContext(ctx, "/usr/bin/apt-config", "shell", "U", "APT::Get::AllowUnauthenticated/b", "F", "APT::Get::Force-Yes/b")
				cmd.Args[0] = "/usr/bin/" + binary
				cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "APT_CONFIG=" + oracle}
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("native query: %v", err)
				}
				values := map[string]bool{"U": false, "F": false}
				for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
					if line == "" {
						continue
					}
					parts := strings.Split(line, "=")
					if len(parts) != 2 || (parts[0] != "U" && parts[0] != "F") || (parts[1] != "'true'" && parts[1] != "'false'") {
						t.Fatalf("unexpected native output %q", out)
					}
					values[parts[0]] = parts[1] == "'true'"
				}
				for i, k := range []string{"U", "F"} {
					if values[k] != wantByBinary[binary][i] {
						t.Fatalf("native %s.%s=%t want %t: %s", binary, k, values[k], wantByBinary[binary][i], out)
					}
					passed = passed && !values[k]
					comparisons++
				}
			}
			r := aptPolicyWithin(cs, root, aptPackage)
			if r.Error || r.Passed != passed {
				t.Fatalf("native/candidate mismatch: %+v", r)
			}
			for binary, values := range wantByBinary {
				for i, key := range []string{"allowunauthenticated", "force-yes"} {
					word := binary + "." + key + "=false"
					if values[i] {
						word = binary + "." + key + "=true"
					}
					if !strings.Contains(r.Actual, word) {
						t.Fatalf("native scalar evidence missing %s: %+v", word, r)
					}
				}
			}
		})
	}
	if _, err := os.Stat("/tmp/alinksec-apt-hook-ran"); !os.IsNotExist(err) {
		t.Fatal("configuration hook unexpectedly ran")
	}
	t.Logf("Native APT install policy: cases=%d comparisons=%d skipped=0; hooks inert; environment/CLI/source trust/installation unverified", len(aptCases()), comparisons)
}
