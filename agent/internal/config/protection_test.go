package config

import "testing"

func TestProtectionPolicyValidationRejectsUnsafeAndUnboundedRules(t *testing.T) {
	file := FileRule{ID: "file", Enabled: true, Match: FileMatch{Paths: []string{"/etc/passwd"}}, Actions: []string{"alert"}}
	login := LoginRule{ID: "login", Enabled: true, Match: LoginMatch{Timezone: "Asia/Shanghai"}, Actions: []string{"alert"}}
	if err := ValidateProtection([]FileRule{file}, []LoginRule{login}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []FileRule{{ID: "file", Match: FileMatch{Paths: []string{"relative"}}}, {ID: "file", Match: FileMatch{Paths: []string{"/a"}, MaxFileBytes: MaxProtectedFileBytes + 1}}, {ID: "file", Match: file.Match, Actions: []string{"kill"}}, {ID: "bad\x00id", Match: file.Match}} {
		if ValidateProtection([]FileRule{bad}, nil) == nil {
			t.Fatalf("bad file rule accepted: %+v", bad)
		}
	}
	for _, mutate := range []func(*LoginRule){func(r *LoginRule) { r.Match.FailureThreshold = 1 }, func(r *LoginRule) { r.Match.BlockDurationSec = 3601 }, func(r *LoginRule) { r.Match.SSHPorts = []int{0} }, func(r *LoginRule) { r.Match.TrustedIPs = []string{"example.com"} }, func(r *LoginRule) { r.Match.Timezone = "unknown/zone" }, func(r *LoginRule) { r.Match.Platforms = []string{"unknown"} }, func(r *LoginRule) { r.Actions = []string{"restore"} }} {
		r := login
		mutate(&r)
		if ValidateProtection(nil, []LoginRule{r}) == nil {
			t.Fatalf("bad login rule accepted: %+v", r)
		}
	}
}

func TestWindowsLoginRequiresExplicitScopeAndContract(t *testing.T) {
	rule := LoginRule{ID: "win", Enabled: true, Match: LoginMatch{WindowsContract: 1, Platforms: []string{"windows"}}, Actions: []string{"alert", "block_ip"}}
	if err := ValidateProtection(nil, []LoginRule{rule}); err != nil {
		t.Fatal(err)
	}
	for _, match := range []LoginMatch{
		{WindowsContract: 2, Platforms: []string{"windows"}},
		{WindowsContract: 1, Platforms: []string{"windows", "linux"}},
		{WindowsContract: 1, Platforms: []string{"windows"}, SSHPorts: []int{22}},
		{WindowsContract: 1, Platforms: []string{"windows"}, WindowsPorts: []int{0}},
		{WindowsContract: 1, Platforms: []string{"windows"}, WindowsLogonTypes: []int{2}},
		{WindowsPorts: []int{3389}},
	} {
		rule.Match = match
		if err := ValidateProtection(nil, []LoginRule{rule}); err == nil {
			t.Fatalf("accepted %+v", match)
		}
	}
}
