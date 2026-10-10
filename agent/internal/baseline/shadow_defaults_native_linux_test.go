//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestNativeShadowAccountDefaults(t *testing.T) {
	if os.Getenv("ALINKSEC_SHADOW_DEFAULTS_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable Ubuntu24 shadow fixture only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-pam-fixture")
	if os.Geteuid() != 0 || os.Getenv("ALINKSEC_SHADOW_DEFAULTS_ISOLATED_REQUIRED") != "true" || err != nil || string(marker) != "isolated-pam-fixture-v1\n" {
		t.Fatal("mandatory isolated container, marker and root required; refusing to modify host accounts")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	version := queryShadowDefaultsVersion(ctx, 5000)
	cancel()
	if version.Error || !shadowDefaultsVersion.MatchString(version.Actual) {
		t.Fatalf("exact Ubuntu24 passwd required: error=%t", version.Error)
	}
	original, err := os.ReadFile(shadowDefaultsTarget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(shadowDefaultsTarget, original, 0644); err != nil {
			t.Error("cannot restore isolated fixture declarations")
		}
	})
	set := func(t *testing.T, body string) {
		t.Helper()
		if err := os.WriteFile(shadowDefaultsTarget, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/etc/default/useradd", []byte("GROUP=65534\nHOME=/home\nINACTIVE=-1\nEXPIRE=\nSHELL=/usr/sbin/nologin\nSKEL=/etc/skel\nCREATE_MAIL_SPOOL=no\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sequence := 0
	create := func(t *testing.T, extra ...string) string {
		t.Helper()
		sequence++
		name := fmt.Sprintf("alinksec-age-%03d", sequence)
		args := []string{"-M", "-l", "-N", "-g", "65534", "-s", "/usr/sbin/nologin"}
		args = append(args, extra...)
		args = append(args, name)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/sbin/useradd", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		if _, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated account creation failed: %v", err)
		}
		return name
	}
	readAge := func(t *testing.T, name string) (int64, int64, int64) {
		t.Helper()
		raw, err := os.ReadFile("/etc/shadow")
		if err != nil {
			t.Fatal("cannot read isolated fixture aging fields")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) != 9 || fields[0] != name {
				continue
			}
			// No password is assigned. Never include a complete shadow record or
			// credential field in test diagnostics, even on assertion failure.
			if fields[1] != "!" && fields[1] != "*" {
				t.Fatal("isolated fixture must keep a locked password field")
			}
			values := []int64{-1, -1, -1}
			for index, field := range fields[3:6] {
				if field != "" {
					value, err := strconv.ParseInt(field, 10, 64)
					if err != nil {
						t.Fatal("invalid isolated aging field")
					}
					values[index] = value
				}
			}
			return values[0], values[1], values[2]
		}
		t.Fatal("isolated account missing")
		return 0, 0, 0
	}
	comparisons := 0
	observe := func(t *testing.T, name string, wantMax, wantWarn int64, maxPass, warnPass bool, kind string) {
		t.Helper()
		min, max, warn := readAge(t, name)
		if max != wantMax || warn != wantWarn {
			t.Fatalf("native aging mismatch: min=%d max=%d warn=%d", min, max, warn)
		}
		for _, option := range []string{"max_days", "warn_days"} {
			s := shadowDefaultsSpec(option)
			result := checkShadowAccountDefaults(&s)
			want := maxPass
			if option == "warn_days" {
				want = warnPass
			}
			if result.Error || result.Passed != want {
				t.Fatalf("declaration %s: %+v", option, result)
			}
			comparisons++
			t.Logf("native Shadow default evidence: case=%s option=%s native_min=%d native_max=%d native_warn=%d passed=%t actual=%s", kind, option, min, max, warn, result.Passed, result.Actual)
		}
	}
	firstAccount := ""
	t.Run("ordinary_default_fields", func(t *testing.T) {
		set(t, "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n")
		firstAccount = create(t)
		observe(t, firstAccount, 90, 7, true, true, "ordinary")
	})
	t.Run("numeric_boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			name              string
			max, warn         int64
			maxPass, warnPass bool
		}{
			{"zero", 0, 7, false, false}, {"disabled", -1, -1, false, false}, {"warning_exceeds_max", 1, 7, true, false}, {"int_max", 2147483647, 7, false, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				set(t, fmt.Sprintf("PASS_MAX_DAYS %d\nPASS_WARN_AGE %d\n", tc.max, tc.warn))
				observe(t, create(t), tc.max, tc.warn, tc.maxPass, tc.warnPass, tc.name)
			})
		}
	})
	t.Run("absent_declarations", func(t *testing.T) {
		set(t, "# No selected declarations\n")
		observe(t, create(t), -1, -1, false, false, "absent")
	})
	t.Run("declared_min_exceeds_max", func(t *testing.T) {
		set(t, "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 91\nPASS_WARN_AGE 7\n")
		observe(t, create(t), 90, 7, false, true, "min_exceeds_max")
	})
	t.Run("command_line_override_is_unverified", func(t *testing.T) {
		set(t, "PASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n")
		observe(t, create(t, "-K", "PASS_MAX_DAYS=-1", "-K", "PASS_WARN_AGE=0"), -1, 0, true, true, "override")
	})
	t.Run("system_accounts_ignore_defaults", func(t *testing.T) {
		set(t, "PASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n")
		observe(t, create(t, "-r"), -1, -1, true, true, "system_account")
	})
	t.Run("existing_account_unchanged", func(t *testing.T) {
		if firstAccount == "" {
			t.Fatal("ordinary fixture missing")
		}
		set(t, "PASS_MAX_DAYS 30\nPASS_WARN_AGE 14\n")
		observe(t, firstAccount, 90, 7, true, true, "existing_account_unchanged")
	})
	t.Run("mandatory_trust_syntax_changes_and_deadline", func(t *testing.T) {
		t.Run("unsafe_inputs", TestShadowDefaultsUnsafeInputs)
		t.Run("finite_syntax", TestShadowDefaultsPoliciesAndFiniteSyntax)
		t.Run("changes_and_deadline", TestShadowDefaultsChangesAndOneDeadline)
	})
	if comparisons != 20 {
		t.Fatalf("mandatory native comparisons: %d", comparisons)
	}
	set(t, string(original))
	result := checkOne(&pb.BaselineCheckSpec{ItemId: "shadow-defaults-product", Check: shadowDefaultsJSON(shadowDefaultsSpec("max_days"))})
	if result.ItemID != "shadow-defaults-product" {
		t.Fatal("dispatcher lost item identity")
	}
	t.Logf("native Shadow read-only product observation: item=%s passed=%t error=%t actual=%s", result.ItemID, result.Passed, result.Error, result.Actual)
	t.Logf("Native Shadow account defaults: product=%s scenarios=8 native_comparisons=%d mandatory_boundaries_executed=true", version.Actual, comparisons)
}
