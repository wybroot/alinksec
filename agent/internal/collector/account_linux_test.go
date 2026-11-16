//go:build linux

package collector

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func accountSnapshot(t *testing.T, passwd, shadow string, passwdErr, shadowErr error) *pb.RptAssetSnapshot {
	t.Helper()
	previous := readAccountFile
	t.Cleanup(func() { readAccountFile = previous })
	readAccountFile = func(path string) ([]byte, error) {
		if path == "/etc/passwd" {
			return []byte(passwd), passwdErr
		}
		if path == "/etc/shadow" {
			return []byte(shadow), shadowErr
		}
		t.Fatalf("unexpected account source %s", path)
		return nil, errors.New("unexpected source")
	}
	return Snapshot([]string{"accounts"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestAccountInvalidPasswdCannotBecomeCompleteOrRoot(t *testing.T) {
	valid := "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n"
	for name, input := range map[string]string{
		"truncated":    "broken:x:1001\n",
		"bad_uid":      "broken:x:bad:1001::/home/broken:/bin/sh\n",
		"bad_gid":      "broken:x:1001:bad::/home/broken:/bin/sh\n",
		"overflow":     "broken:x:4294967296:1001::/home/broken:/bin/sh\n",
		"duplicate":    valid,
		"empty_name":   ":x:1001:1001::/home/broken:/bin/sh\n",
		"extra_field":  "broken:x:1001:1001::/home/broken:/bin/sh:extra\n",
		"control_byte": "broken:x:1001:1001::/home/broken:/bin/sh\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			snap := accountSnapshot(t, valid+input, "alice:!:1:0:99999:7:::\n", nil, nil)
			state := snap.Collections[0]
			if state.Status != pb.AssetCollection_FAILED || state.Error != "account_parse_failed" || len(snap.Accounts) != 0 {
				t.Fatalf("malformed account input became successful inventory: %v", snap)
			}
		})
	}
}

func TestAccountUnknownShadowIsNotAnEmptyPassword(t *testing.T) {
	for _, tc := range []struct {
		name, shadow string
		err          error
	}{
		{"unreadable", "", errors.New("denied")},
		{"missing_entry", "other:!:1:0:99999:7:::\n", nil},
		{"truncated", "alice:\n", nil},
		{"duplicate", "alice:!:1:0:99999:7:::\nalice::1:0:99999:7:::\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := accountSnapshot(t, "alice:x:1000:1000::/home/alice:/bin/sh\n", tc.shadow, nil, tc.err)
			if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error == "" || len(snap.Accounts) != 1 || snap.Accounts[0].Risky {
				t.Fatalf("unknown password state became empty password or complete inventory: %v", snap)
			}
		})
	}
}

func TestAccountPasswordFieldAndDefaultShell(t *testing.T) {
	snap := accountSnapshot(t, "locked:!:1000:1000::/home/locked:/bin/sh\nempty::1001:1001::/home/empty:\nshadow:x:1002:1002::/home/shadow:/bin/sh\nclone:!:0:0::/root:/bin/sh\n", "shadow::1:0:99999:7:::\n", nil, nil)
	if snap.Collections[0].Status != pb.AssetCollection_COMPLETE || len(snap.Accounts) != 4 {
		t.Fatalf("valid account inputs rejected: %v", snap)
	}
	if snap.Accounts[0].Risky || !snap.Accounts[1].LoginEnabled || !snap.Accounts[1].Risky || !snap.Accounts[2].Risky || !snap.Accounts[3].Risky {
		t.Fatalf("password source/default shell semantics incorrect: %v", snap)
	}
}

func TestAccountDirectPasswordDoesNotRequireOptionalShadow(t *testing.T) {
	for _, passwd := range []string{"", "locked:!:1000:1000::/home/locked:/bin/sh\nempty::1001:1001::/home/empty:\n"} {
		snap := accountSnapshot(t, passwd, "", nil, errors.New("optional shadow unavailable"))
		if snap.Collections[0].Status != pb.AssetCollection_COMPLETE {
			t.Fatalf("unreferenced optional shadow invalidated trusted passwd inventory: %v", snap.Collections)
		}
		if passwd != "" && (snap.Accounts[0].Risky || !snap.Accounts[1].Risky) {
			t.Fatal("direct password semantics changed")
		}
	}
}

func TestAccountReadFailureAndTrueEmptyInventory(t *testing.T) {
	snap := accountSnapshot(t, "", "", errors.New("denied"), nil)
	if snap.Collections[0].Status != pb.AssetCollection_FAILED {
		t.Fatal("read failure reported complete")
	}
	empty := accountSnapshot(t, "", "", nil, nil)
	if empty.Collections[0].Status != pb.AssetCollection_COMPLETE || len(empty.Accounts) != 0 {
		t.Fatal("valid empty inventory rejected")
	}
}
