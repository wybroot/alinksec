package baseline

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func aptSpec() *CheckSpec {
	return &CheckSpec{Type: "apt_install_policy", Target: "/etc/apt", Operator: "eq", Expected: aptPolicyReference, TimeoutMs: 1000}
}
func TestAPTDefinitionBoundary(t *testing.T) {
	valid := map[string]any{"type": "apt_install_policy", "target": "/etc/apt", "operator": "eq", "expected": aptPolicyReference}
	for key, value := range map[string]any{"target": "/tmp/apt", "operator": "regex", "expected": "false", "cmd": nil, "option": nil, "perm": "0644", "owner": "0", "group": "0", "uid_min": 0, "connection": nil} {
		changed := map[string]any{}
		for k, v := range valid {
			changed[k] = v
		}
		changed[key] = value
		raw, _ := json.Marshal(changed)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	raw, _ := json.Marshal(valid)
	cs, err := ParseCheck(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if r := checkAPTPolicy(cs); !r.Error || r.Passed {
			t.Fatalf("executed Linux check: %+v", r)
		}
	}
}
func TestAPTUnknownSyntaxAndBooleans(t *testing.T) {
	for _, raw := range []string{
		`APT::Get::AllowUnauthenticated"false";`,
		`#include "/tmp/override";`, `#x-apt-configure-index "x";`, `APT::Get::AllowUnauthenticated true;`,
		`APT::Get::AllowUnauthenticated "false"`, `APT { Get { AllowUnauthenticated "false"; };`,
		`APT "value" { Get { AllowUnauthenticated "false"; }; };`, `APT { #clear APT; };`,
		`APT::Get::AllowUnauthenticated:: "false";`, `APT::Get::Force-Yes { "false"; };`,
		`Dir::Etc::main "/tmp/apt";`, `Dir "/";`, `RootDir "/tmp";`, `#clear Dir;`,
		`Binary::apt-get::Dir::Etc::Parts "elsewhere";`, `#clear Binary::apt::Dir;`,
		`APT::Get::AllowUnauthenticated "fal\se";`, `/* mixed */ APT::Get::Force-Yes "false";`,
		`/* unterminated`, `APT::Get::AllowUnauthenticated "false` + "\n" + `";`,
		strings.Repeat("APT {", 17) + strings.Repeat("};", 17),
	} {
		tree := aptTree{}
		if err := tree.parse(raw + "\n"); err == nil {
			t.Fatalf("accepted unsupported %q", raw)
		}
	}
	for _, value := range []string{"flase", "2", "-1", " 0", "0x0", "00", "true ", "FALSE\t"} {
		tree := aptTree{"apt::get::allowunauthenticated": value}
		if _, _, err := tree.resolved("apt", aptBoolKeys[0]); err == nil {
			t.Fatalf("accepted boolean %q", value)
		}
	}
}
