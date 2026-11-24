//go:build windows

package collector

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

type fakeUninstallReader struct {
	roots map[string]*fakeUninstallRoot
}

type fakeUninstallRoot struct {
	openErr error
	listErr error
	names   []string
	entries map[string]*fakeUninstallEntry
}

type fakeUninstallEntry struct {
	openErr error
	values  map[string]string
	errs    map[string]error
}

func (r fakeUninstallReader) OpenRoot(path string) (winUninstallRoot, error) {
	root, ok := r.roots[path]
	if !ok {
		return nil, registry.ErrNotExist
	}
	if root.openErr != nil {
		return nil, root.openErr
	}
	return root, nil
}

func (r *fakeUninstallRoot) ReadSubKeyNames() ([]string, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.names, nil
}

func (r *fakeUninstallRoot) OpenEntry(subKey string) (winUninstallEntry, error) {
	entry, ok := r.entries[subKey]
	if !ok {
		return nil, registry.ErrNotExist
	}
	if entry.openErr != nil {
		return nil, entry.openErr
	}
	return entry, nil
}

func (r *fakeUninstallRoot) Close() error { return nil }

func (e *fakeUninstallEntry) GetStringValue(name string) (string, error) {
	if err := e.errs[name]; err != nil {
		return "", err
	}
	v, ok := e.values[name]
	if !ok {
		return "", registry.ErrNotExist
	}
	return v, nil
}

func (e *fakeUninstallEntry) Close() error { return nil }

func TestParseWinDateRejectsInvalidCalendarDates(t *testing.T) {
	if parseWinDate("20240115") <= 0 {
		t.Fatal("valid date rejected")
	}
	for _, bad := range []string{"", "2024", "19790101", "20240231", "20241301", "abcd0101"} {
		if got := parseWinDate(bad); got != 0 {
			t.Fatalf("parseWinDate(%q) = %d, want 0", bad, got)
		}
	}
}

func TestCollectWindowsSoftwareValidationAndErrors(t *testing.T) {
	const root64 = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	const root32 = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`

	t.Run("dedup_preserves_distinct_versions_and_skips_vanished_subkey", func(t *testing.T) {
		snap := &pb.RptAssetSnapshot{}
		collectWindowsSoftware(snap, fakeUninstallReader{roots: map[string]*fakeUninstallRoot{
			root64: {
				names: []string{"app64", "vanished", "blank", "app_v2"},
				entries: map[string]*fakeUninstallEntry{
					"app64":  {values: map[string]string{"DisplayName": "App", "DisplayVersion": "1.0", "Publisher": "Acme", "InstallDate": "20240501"}},
					"blank":  {values: map[string]string{"DisplayName": "   "}},
					"app_v2": {values: map[string]string{"DisplayName": "App", "DisplayVersion": "2.0", "Publisher": "Acme"}},
				},
			},
			root32: {
				names: []string{"app32_dup"},
				entries: map[string]*fakeUninstallEntry{
					"app32_dup": {values: map[string]string{"DisplayName": "App", "DisplayVersion": "1.0", "Publisher": "Acme"}},
				},
			},
		}})
		if snap.SoftwareInventory.Status != pb.SoftwareInventory_COMPLETE || snap.SoftwareInventory.Error != "" || len(snap.Software) != 2 {
			t.Fatalf("got status=%+v software=%+v", snap.SoftwareInventory, snap.Software)
		}
	})

	t.Run("permission_denied_classified", func(t *testing.T) {
		snap := &pb.RptAssetSnapshot{}
		collectWindowsSoftware(snap, fakeUninstallReader{roots: map[string]*fakeUninstallRoot{
			root64: {openErr: os.ErrPermission},
		}})
		if snap.SoftwareInventory.Status != pb.SoftwareInventory_FAILED || snap.SoftwareInventory.Error != "registry_permission_denied" || len(snap.Software) != 0 {
			t.Fatalf("got status=%+v software=%d", snap.SoftwareInventory, len(snap.Software))
		}
	})

	t.Run("query_failed_classified", func(t *testing.T) {
		snap := &pb.RptAssetSnapshot{}
		collectWindowsSoftware(snap, fakeUninstallReader{roots: map[string]*fakeUninstallRoot{
			root64: {
				names: []string{"bad"},
				entries: map[string]*fakeUninstallEntry{
					"bad": {errs: map[string]error{"DisplayName": errors.New("corrupt key")}},
				},
			},
		}})
		if snap.SoftwareInventory.Status != pb.SoftwareInventory_FAILED || snap.SoftwareInventory.Error != "registry_query_failed" || len(snap.Software) != 0 {
			t.Fatalf("got status=%+v software=%d", snap.SoftwareInventory, len(snap.Software))
		}
	})

	t.Run("oversized_and_nul_values_rejected", func(t *testing.T) {
		for _, tc := range []map[string]string{
			{"DisplayName": "bad\x00app", "DisplayVersion": "1.0"},
			{"DisplayName": "App", "DisplayVersion": strings.Repeat("1", 256)},
		} {
			snap := &pb.RptAssetSnapshot{}
			collectWindowsSoftware(snap, fakeUninstallReader{roots: map[string]*fakeUninstallRoot{
				root64: {
					names:   []string{"item"},
					entries: map[string]*fakeUninstallEntry{"item": {values: tc}},
				},
			}})
			if snap.SoftwareInventory.Status != pb.SoftwareInventory_FAILED || snap.SoftwareInventory.Error != "registry_output_invalid_or_limited" || len(snap.Software) != 0 {
				t.Fatalf("got status=%+v software=%d", snap.SoftwareInventory, len(snap.Software))
			}
		}
	})
}
