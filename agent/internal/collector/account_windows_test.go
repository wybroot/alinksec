//go:build windows

package collector

import (
	"errors"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestCollectWindowsAccountsPolicyAndValidation(t *testing.T) {
	oldQuery := queryWindowsAccounts
	t.Cleanup(func() { queryWindowsAccounts = oldQuery })

	t.Run("wmi_read_failure", func(t *testing.T) {
		queryWindowsAccounts = func() ([]winUserAccount, error) {
			return nil, errors.New("wmi failed")
		}
		snap := Snapshot([]string{"accounts"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_FAILED || snap.Collections[0].Error != "account_read_failed" || len(snap.Accounts) != 0 {
			t.Fatalf("got %+v", snap)
		}
	})

	t.Run("invalid_and_duplicate_rows_rejected_without_partial_publish", func(t *testing.T) {
		valid := winUserAccount{Name: "Alice", Disabled: false, PasswordRequired: true, SID: "S-1-5-21-1"}
		for name, bad := range map[string][]winUserAccount{
			"blank":       {valid, {Name: "  "}},
			"control":     {valid, {Name: "bad\nuser"}},
			"duplicate":   {valid, {Name: "alice", Disabled: true, PasswordRequired: true}},
			"oversized":   {{Name: string(make([]byte, 256))}},
		} {
			t.Run(name, func(t *testing.T) {
				queryWindowsAccounts = func() ([]winUserAccount, error) { return bad, nil }
				snap := Snapshot([]string{"accounts"}, testLogger())
				if snap.Collections[0].Status != pb.AssetCollection_FAILED || snap.Collections[0].Error != "account_parse_failed" || len(snap.Accounts) != 0 {
					t.Fatalf("%s: got status=%+v accounts=%d", name, snap.Collections[0], len(snap.Accounts))
				}
			})
		}
	})

	t.Run("password_required_risk_and_empty_success", func(t *testing.T) {
		queryWindowsAccounts = func() ([]winUserAccount, error) {
			return []winUserAccount{
				{Name: "Admin", Disabled: false, PasswordRequired: true},
				{Name: "NoPassEnabled", Disabled: false, PasswordRequired: false},
				{Name: "NoPassDisabled", Disabled: true, PasswordRequired: false},
			}, nil
		}
		snap := Snapshot([]string{"accounts"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_COMPLETE || len(snap.Accounts) != 3 {
			t.Fatalf("got %+v", snap)
		}
		if snap.Accounts[0].Risky || !snap.Accounts[0].LoginEnabled {
			t.Fatalf("Admin unexpected: %+v", snap.Accounts[0])
		}
		if !snap.Accounts[1].Risky || !snap.Accounts[1].LoginEnabled || snap.Accounts[1].RiskyReason == "" {
			t.Fatalf("NoPassEnabled must be flagged risky: %+v", snap.Accounts[1])
		}
		if snap.Accounts[2].Risky || snap.Accounts[2].LoginEnabled {
			t.Fatalf("disabled account must not flag login-enabled risk: %+v", snap.Accounts[2])
		}

		queryWindowsAccounts = func() ([]winUserAccount, error) { return nil, nil }
		empty := Snapshot([]string{"accounts"}, testLogger())
		if empty.Collections[0].Status != pb.AssetCollection_COMPLETE || len(empty.Accounts) != 0 {
			t.Fatalf("valid empty failed: %+v", empty)
		}
	})
}
