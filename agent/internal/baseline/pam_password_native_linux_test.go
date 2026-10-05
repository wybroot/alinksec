//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativePAMPassword(t *testing.T) {
	if os.Getenv("ALINKSEC_PAM_ISOLATED_REQUIRED") != "true" {
		t.Skip("disposable PAM fixture image required; never modify host PAM or credentials")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-pam-fixture")
	if err != nil || string(marker) != "isolated-pam-fixture-v1\n" || os.Geteuid() != 0 {
		t.Fatal("refuse native password changes outside the dedicated isolated fixture image")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("dedicated container required")
	}
	paths := systemPAMPaths()
	raw, err := os.ReadFile("../../../deploy/baseline/packages/pam/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &document); err != nil || len(document.Items) != 2 {
		t.Fatal("shipped two-item PAM candidate required")
	}
	specs := map[string]*CheckSpec{}
	for _, item := range document.Items {
		spec, err := ParseCheck(string(item.Check))
		if err != nil {
			t.Fatal(err)
		}
		specs[spec.Option] = spec
	}
	if specs["quality"] == nil || specs["unix_hash"] == nil {
		t.Fatal("both shipped PAM options required")
	}
	configure := func(chain, policy string) {
		t.Helper()
		pamWrite(t, filepath.Join(paths.directory, "passwd"), "@include common-password\n")
		pamWrite(t, filepath.Join(paths.directory, "common-password"), chain)
		pamWrite(t, paths.quality, policy)
		if err := os.RemoveAll(paths.quality + ".d"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(paths.quality+".d", 0700); err != nil {
			t.Fatal(err)
		}
	}
	strong := "R4!vQ8#mL2@zN6%pT9"
	singleClass := "marigoldsparrowcypress"
	short := "x"
	probe := func(first, second string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/local/bin/alinksec-pam-probe")
		cmd.Stdin = strings.NewReader(first + "\n" + second + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("isolated native PAM probe failed: %v", err)
		}
		value := strings.TrimSpace(string(out))
		if strings.Contains(value, first) || strings.Contains(value, second) || strings.Contains(value, "$y$") || strings.Contains(value, "$6$") {
			t.Fatal("native credential material escaped")
		}
		if !strings.HasPrefix(value, "rc=") {
			t.Fatal("missing native outcome")
		}
		return value
	}
	check := func(option string, wantPass, wantError bool) ItemResult {
		t.Helper()
		result := pamPasswordWithin(specs[option], paths)
		if result.Error != wantError || result.Passed != wantPass {
			t.Fatalf("shipped %s reference: %+v", option, result)
		}
		return result
	}
	configure(pamQuality+pamWriter, pamPolicy+"dictcheck=0\n")
	for _, option := range []string{"quality", "unix_hash"} {
		result := check(option, true, false)
		t.Logf("native PAM configuration evidence (isolated Ubuntu24 fixture): %s %s", option, result.Actual)
	}
	value := probe(strong, strong)
	if !strings.Contains(value, "rc=0 algorithm=yescrypt first=1 second=1") {
		t.Fatalf("strong token did not produce actual yescrypt: %s", value)
	}
	t.Logf("native PAM behavior evidence (isolated Ubuntu24 fixture): strong-token %s", value)
	for _, token := range []string{short, singleClass} {
		value := probe(token, token)
		if strings.HasPrefix(value, "rc=0 ") {
			t.Fatal("weak token accepted by strong policy")
		}
		t.Logf("native PAM behavior evidence (isolated Ubuntu24 fixture): rejected-token %s", value)
	}
	t.Run("drop-ins before main and module arguments last", func(t *testing.T) {
		configure(pamQuality+pamWriter, pamPolicy+"dictcheck=0\n")
		pamWrite(t, paths.quality+".d/10-length.conf", "minlen=30\n")
		pamWrite(t, paths.quality+".d/90-length.conf", "minlen=26\n")
		pamWrite(t, paths.quality+".d/ignored.conf.backup.conf", "minlen=40\n")
		check("quality", true, false)
		if value := probe(strong, strong); !strings.HasPrefix(value, "rc=0 ") {
			t.Fatalf("native main precedence: %s", value)
		}
		pamWrite(t, filepath.Join(paths.directory, "common-password"), "password requisite pam_pwquality.so minlen=30\n"+pamWriter)
		result := check("quality", true, false)
		if !strings.Contains(result.Actual, "minlen=30") {
			t.Fatal("module override missing")
		}
		if value := probe(strong, strong); strings.HasPrefix(value, "rc=0 ") {
			t.Fatal("native module override ignored")
		}
	})
	t.Run("root and enforcing exceptions", func(t *testing.T) {
		for _, policy := range []string{strings.ReplaceAll(pamPolicy, "enforce_for_root\n", ""), pamPolicy + "enforcing=0\n"} {
			configure(pamQuality+pamWriter, policy+"dictcheck=0\n")
			check("quality", false, false)
			if value := probe(short, short); !strings.HasPrefix(value, "rc=0 ") {
				t.Fatalf("native exception not observed: %s", value)
			}
		}
		configure(pamQuality+pamWriter, pamPolicy+"enforce_for_root=0\ndictcheck=0\n")
		check("quality", true, false)
		if value := probe(short, short); strings.HasPrefix(value, "rc=0 ") {
			t.Fatal("SET flag value wrongly disables root enforcement")
		}
	})
	t.Run("module class override", func(t *testing.T) {
		configure("password requisite pam_pwquality.so minclass=0\n"+pamWriter, pamPolicy+"dictcheck=0\n")
		check("quality", false, false)
		if value := probe(singleClass, singleClass); !strings.HasPrefix(value, "rc=0 ") {
			t.Fatalf("native class override not observed: %s", value)
		}
	})
	t.Run("writer must consume the checked token", func(t *testing.T) {
		configure(pamQuality+strings.ReplaceAll(pamWriter, " use_authtok", ""), pamPolicy+"dictcheck=0\n")
		check("quality", false, false)
		value := probe(strong, short)
		if !strings.Contains(value, "rc=0 algorithm=yescrypt first=0 second=1") {
			t.Fatalf("native second unvalidated token not observed: %s", value)
		}
		t.Logf("native PAM behavior evidence (isolated Ubuntu24 fixture): unbound-writer %s", value)
	})
	t.Run("early permit bypass is unconfirmed", func(t *testing.T) {
		configure("password sufficient pam_permit.so\n"+pamQuality+pamWriter, pamPolicy)
		check("quality", false, true)
		check("unix_hash", false, true)
		value := probe(strong, strong)
		if !strings.HasPrefix(value, "rc=0 ") || !strings.Contains(value, "first=0") {
			t.Fatalf("native early bypass not observed: %s", value)
		}
		t.Logf("native PAM behavior evidence (isolated Ubuntu24 fixture): bypass %s", value)
	})
	t.Run("hash declaration compared with actual new hash", func(t *testing.T) {
		configure(pamQuality+strings.ReplaceAll(pamWriter, "yescrypt", "sha512"), pamPolicy+"dictcheck=0\n")
		result := check("unix_hash", false, false)
		value := probe(strong, strong)
		if !strings.Contains(value, "rc=0 algorithm=sha512 first=1") {
			t.Fatalf("native hash selection: %s", value)
		}
		t.Logf("native PAM behavior evidence (isolated Ubuntu24 fixture): different-algorithm %s %s", result.Actual, value)
	})
	t.Run("nested includes and continuation", func(t *testing.T) {
		configure("password requisite pam_pwquality.so \\\n retry=1\n"+pamWriter, pamPolicy+"dictcheck=0\n")
		pamWrite(t, filepath.Join(paths.directory, "passwd"), "password include nested\n")
		pamWrite(t, filepath.Join(paths.directory, "nested"), "@include common-password\n")
		check("quality", true, false)
		if value := probe(strong, strong); !strings.HasPrefix(value, "rc=0 ") {
			t.Fatal(fmt.Sprintf("native includes/continuation: %s", value))
		}
	})
}
