//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestNativeAppArmor(t *testing.T) {
	if os.Getenv("ALINKSEC_APPARMOR_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable AppArmor runner only")
	}
	if os.Geteuid() != 0 || os.Getenv("ALINKSEC_APPARMOR_FIXTURES_ALLOWED") != "true" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("root and disposable runner authorization required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := fmt.Sprintf("alinksec-apparmor-native-%d", os.Getpid())
	path := filepath.Join(t.TempDir(), "unattached-profile")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := func(executable string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		return cmd.Output()
	}
	read := func() appArmorSnapshot {
		t.Helper()
		s, err := readAppArmorSnapshot(ctx, "/sys", true)
		if err != nil || evaluateAppArmor(s).Error {
			t.Fatal("native root view must be readable with the supported ABI", err, evaluateAppArmor(s))
		}
		return s
	}
	initial := read()
	initialProfiles, _ := parseAppArmorProfiles(initial.Values["profiles"])
	if initial.Values["enabled"] != "Y\n" || strings.TrimSuffix(initial.Values["mode"], "\n") != "enforce" || initialProfiles[name] != "" {
		t.Fatalf("enabled enforcing root view and unused unique fixture name required: enabled=%q mode=%q fixture_exists=%t", initial.Values["enabled"], initial.Values["mode"], initialProfiles[name] != "")
	}
	loaded := false
	t.Cleanup(func() {
		if loaded {
			// Cleanup gets its own deadline even if the observation context expired.
			cleanupCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			cmd := exec.CommandContext(cleanupCtx, "/usr/sbin/apparmor_parser", "-R", "-K", path)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			if err := cmd.Run(); err != nil {
				t.Error("unique profile cleanup failed", err)
			}
		}
	})
	independent := func() map[string]string {
		t.Helper()
		raw, err := command("/usr/sbin/aa-status", "--json")
		if err != nil || len(raw) > 1024*1024 {
			t.Fatal("independent aa-status failed or exceeded limit", err)
		}
		var doc struct {
			Profiles map[string]json.RawMessage `json:"profiles"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Profiles == nil {
			t.Fatal("unsupported aa-status JSON")
		}
		out := map[string]string{}
		for key, value := range doc.Profiles {
			var mode string
			if json.Unmarshal(value, &mode) == nil {
				if !appArmorMode(mode) {
					t.Fatal("unsupported independent mode")
				}
				out[key] = mode
				continue
			}
			var names []string
			if !appArmorMode(key) || json.Unmarshal(value, &names) != nil {
				t.Fatal("unsupported independent profile shape")
			}
			for _, profile := range names {
				if out[profile] != "" {
					t.Fatal("duplicate independent profile")
				}
				out[profile] = key
			}
		}
		return out
	}
	observations := 0
	check := func(mode string, fixturePresent bool) {
		t.Helper()
		s := read()
		profiles, err := parseAppArmorProfiles(s.Values["profiles"])
		if err != nil || !reflect.DeepEqual(profiles, independent()) {
			t.Fatal("kernel inventory differs from independent aa-status", err)
		}
		if fixturePresent && profiles[name] != mode || !fixturePresent && profiles[name] != "" {
			t.Fatal("unique fixture mode mismatch")
		}
		want := len(profiles) > 0 && strings.TrimSuffix(s.Values["mode"], "\n") == "enforce"
		for _, actualMode := range profiles {
			want = want && actualMode == "enforce"
		}
		r := checkOne(&pb.BaselineCheckSpec{ItemId: "apparmor-product", Check: appArmorJSON()})
		if r.Error || r.Passed != want || r.ItemID != "apparmor-product" || strings.Contains(r.Actual+r.Message, name) {
			t.Fatal(r)
		}
		observations++
		t.Logf("native AppArmor %s: independent_inventory_match=true fixture_present=%t profiles=%d passed=%t error=%t item=%s actual=%s", mode, fixturePresent, len(profiles), r.Passed, r.Error, r.ItemID, r.Actual)
	}
	check("initial", false)
	for _, mode := range []string{"enforce", "complain", "kill", "unconfined", "enforce"} {
		flags := ""
		if mode != "enforce" {
			flags = " flags=(" + mode + ")"
		}
		// A named profile with no attachment is never attached to an application.
		if err := os.WriteFile(path, []byte("profile "+name+flags+" { }\n"), 0600); err != nil {
			t.Fatal(err)
		}
		loaded = true
		if _, err := command("/usr/sbin/apparmor_parser", "-r", "-K", path); err != nil {
			t.Fatal("load isolated unattached profile", mode, err)
		}
		check(mode, true)
	}
	if _, err := command("/usr/sbin/apparmor_parser", "-R", "-K", path); err != nil {
		t.Fatal("remove unique fixture", err)
	}
	loaded = false
	check("removed", false)
	remaining, err := parseAppArmorProfiles(read().Values["profiles"])
	if err != nil || !reflect.DeepEqual(initialProfiles, remaining) {
		t.Fatal("original loaded mode inventory was not restored", err)
	}
	t.Run("mandatory_definitions", TestAppArmorDefinitionBoundary)
	t.Run("mandatory_states_and_redaction", TestAppArmorRuntimeStatesAndRedaction)
	t.Run("mandatory_inventory_limits", TestAppArmorInventoryLimits)
	t.Run("mandatory_changes_and_deadline", TestAppArmorChangesFailuresAndDeadline)
	t.Run("mandatory_protected_reader", TestAppArmorProtectedKernelReader)
	t.Logf("Native AppArmor: native_observations=%d independent_inventory_comparisons=%d mandatory_boundaries_executed=true application_activations=0 existing_profile_changes=0 global_mode_changes=0 fixture_removed=true", observations, observations)
}
