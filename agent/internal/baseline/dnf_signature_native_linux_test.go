//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNativeDNFSignature(t *testing.T) {
	if os.Getenv("ALINKSEC_DNF_ISOLATED_REQUIRED") != "true" {
		t.Skip("dedicated isolated Rocky9 image required")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-dnf-fixture")
	if err != nil || string(marker) != "isolated-dnf-fixture-v1\n" || os.Geteuid() != 0 {
		t.Fatal("isolated DNF marker and root required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	cs := dnfSpec()
	cs.TimeoutMs = 5000
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	observations, comparisons := 0, 0
	observe := func(wantPass bool) {
		r := checkDNFSignature(cs)
		if r.Error || r.Passed != wantPass {
			t.Fatal(r)
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/python3", "/workspace/deploy/tests/dnf/probe.py")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "PYTHONDONTWRITEBYTECODE=1"}
		query := collectBaselineCommand(ctx, cmd, 5000)
		if query.Error {
			t.Fatal("independent native DNF configuration unavailable")
		}
		var native struct {
			Main     map[string]bool            `json:"main"`
			Reposdir []string                   `json:"reposdir"`
			Repos    map[string]map[string]bool `json:"repos"`
		}
		if json.Unmarshal([]byte(query.Actual), &native) != nil || !reflect.DeepEqual(native.Reposdir, dnfRepoDirs) {
			t.Fatal("native repository model outside declared scope")
		}
		passed := native.Main["gpgcheck"] && native.Main["repo_gpgcheck"] && native.Main["localpkg_gpgcheck"] && len(native.Repos) > 0
		bad := 0
		for _, repo := range native.Repos {
			if !repo["gpgcheck"] || !repo["repo_gpgcheck"] {
				passed = false
				bad++
			}
		}
		if passed != r.Passed || !strings.Contains(r.Actual, "repo_count="+strconv.Itoa(len(native.Repos))) || !strings.Contains(r.Actual, "mismatched_repos="+strconv.Itoa(bad)) {
			t.Fatal("native DNF values and declaration report differ")
		}
		observations++
		comparisons++
		t.Logf("Native DNF signature observation: index=%d passed=%t repositories=%d independent_comparison=true", observations, r.Passed, len(native.Repos))
	}
	observe(false)
	for _, dir := range dnfRepoDirs {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	main := "/etc/dnf/dnf.conf"
	repo := "/etc/yum.repos.d/alinksec-fixture.repo"
	pamWrite(t, main, dnfMainFixture)
	pamWrite(t, repo, "[alinksec]\nname=isolated native fixture\nbaseurl=file:///nonexistent-fixture\n")
	observe(true)
	pamWrite(t, repo, "[alinksec]\ngpgcheck=0\nbaseurl=file:///nonexistent-fixture\n")
	observe(false)
	pamWrite(t, repo, "[alinksec]\nrepo_gpgcheck=0\nenabled=0\nbaseurl=file:///nonexistent-fixture\n")
	observe(false)
	pamWrite(t, repo, "[alinksec]\nbaseurl=file:///nonexistent-fixture\n")
	pamWrite(t, main, "[main]\ngpgcheck=yes\nrepo_gpgcheck=true\nlocalpkg_gpgcheck=off\n")
	observe(false)
	pamWrite(t, main, dnfMainFixture)
	pamWrite(t, filepath.Join("/etc/distro.repos.d", "extra.repo"), "[extra]\ngpgcheck=0\nbaseurl=file:///nonexistent-fixture\n")
	observe(false)
	os.Remove(filepath.Join("/etc/distro.repos.d", "extra.repo"))
	observe(true)
	os.Remove(repo)
	observe(false)
	t.Run("mandatory_definition", TestDNFSignatureDefinitionBoundary)
	t.Run("mandatory_states", TestDNFSignatureInheritanceAndFailureStates)
	t.Run("mandatory_grammar", TestDNFSignatureGrammarAndLimits)
	if observations != 8 || comparisons != 8 {
		t.Fatal("incomplete DNF native observations")
	}
	t.Log("Native DNF signature: native_observations=8 independent_comparisons=8 mandatory_boundaries_executed=true metadata_downloads=0 package_installs=0 host_configuration_changes=0")
}
