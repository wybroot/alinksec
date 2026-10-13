package fixer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePkgPayloadRequiresChecksum(t *testing.T) {
	_, err := parsePkgPayload(`{"pkg_name":"openssl","target_version":"3.0.0","download_url":"https://console.example.test/package"}`)
	if err == nil {
		t.Fatal("payload without sha256 was accepted")
	}
}

func TestPackageVerificationRetainsEpochAndRelease(t *testing.T) {
	for _, tc := range []struct {
		actual, target string
		match          bool
	}{
		{"0:3.0.7-27.el9", "3.0.7-27.el9", true},
		{"0001:3.0.7-27.el9", "1:3.0.7-27.el9", true},
		{"1:3.0.7-27.el9", "3.0.7-27.el9", false},
		{"1:3.0.7-27.el9", "1:3.0.7-28.el9", false},
		{"1:3.0.7-27.el9", "1:3.0.7", false},
		{"", "", false},
	} {
		if got := packageVersionMatches("rpm", tc.actual, tc.target); got != tc.match {
			t.Fatalf("package identity match=%v want=%v", got, tc.match)
		}
	}
}

func TestParsePkgPayloadAcceptsCompletePackageMetadata(t *testing.T) {
	pkg, err := parsePkgPayload(completeRepairPayload(t))
	if err != nil {
		t.Fatalf("parsePkgPayload() error = %v", err)
	}
	if pkg.Sha256 != strings.Repeat("a", 64) || pkg.Inventory.Contract != 2 {
		t.Fatal("complete checksum or approved identity lost")
	}
}

func completeRepairPayload(t *testing.T) string {
	t.Helper()
	payload := PkgPayload{RepoType: "deb", PkgName: "fixture", TargetVersion: "2.0-1", DownloadURL: "https://fixture.invalid/package", Sha256: strings.Repeat("a", 64), FindingID: "1", DispatchDeadlineMS: time.Now().Add(5 * time.Minute).UnixMilli(),
		Inventory: PackageInstallation{Contract: 2, OSType: 1, Source: "dpkg", Architecture: "amd64", DistroID: "ubuntu", DistroVersion: "24.04", InstalledVersion: "1.0-1"}}
	value, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func TestPackageRepairRejectsLegacyAndIncompleteContracts(t *testing.T) {
	for _, mutate := range []func(*PkgPayload){
		func(p *PkgPayload) { p.Inventory = PackageInstallation{} }, func(p *PkgPayload) { p.Inventory.Contract = 1 },
		func(p *PkgPayload) { p.Inventory.Architecture = "*" }, func(p *PkgPayload) { p.Inventory.DistroID = "" },
		func(p *PkgPayload) { p.Inventory.InstalledVersion = "" }, func(p *PkgPayload) { p.Inventory.OSType = 2 },
		func(p *PkgPayload) { p.Inventory.Source = "rpm" }, func(p *PkgPayload) { p.Sha256 = "abc123" },
		func(p *PkgPayload) { p.PkgName = "--help" }, func(p *PkgPayload) { p.RepoType = "msu" },
		func(p *PkgPayload) { p.DispatchDeadlineMS = 0 }, func(p *PkgPayload) { p.DispatchDeadlineMS = time.Now().Add(-time.Minute).UnixMilli() },
	} {
		var payload PkgPayload
		if err := json.Unmarshal([]byte(completeRepairPayload(t)), &payload); err != nil {
			t.Fatal(err)
		}
		mutate(&payload)
		value, _ := json.Marshal(payload)
		if _, err := parsePkgPayload(string(value)); err == nil {
			t.Fatal("unsupported or incomplete command accepted")
		}
	}
}

func TestPackageRepairRejectsAMismatchedFindingBeforeInspectingTheHost(t *testing.T) {
	result := fixPackageWithOperations(&pb.FixItem{RefId: "2", Payload: completeRepairPayload(t)}, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), packageOperations{})
	if result.GetSuccess() || result.GetVerified() || !strings.Contains(result.GetLog(), "目标不一致") {
		t.Fatal("mismatched approved finding accepted")
	}
}

func TestPackageRepairStopsBeforeInstallationAndRequiresPostInstallIdentity(t *testing.T) {
	for _, scenario := range []string{"complete", "identity-before-download", "identity-after-download", "window-after-download", "wrong-name", "wrong-source", "wrong-version", "wrong-architecture", "unreadable-package", "identity-after-install", "query-after-install", "installation-failed"} {
		t.Run(scenario, func(t *testing.T) {
			value := completeRepairPayload(t)
			p, err := parsePkgPayload(value)
			if err != nil {
				t.Fatal(err)
			}
			queries, downloads, installs := 0, 0, 0
			ops := packageOperations{disk: func() (float64, error) { return 1000, nil }, identity: func(string) (PackageInstallation, error) {
				queries++
				current := p.Inventory
				if queries == 3 {
					current.InstalledVersion = p.TargetVersion
				}
				if (scenario == "identity-before-download" && queries == 1) || (scenario == "identity-after-download" && queries == 2) || (scenario == "identity-after-install" && queries == 3) {
					current.Architecture = "i386"
				}
				if scenario == "query-after-install" && queries == 3 {
					return PackageInstallation{}, errors.New("query failed")
				}
				return current, nil
			}, download: func(_ string, active *PkgPayload) (string, error) {
				downloads++
				if scenario == "window-after-download" {
					active.DispatchDeadlineMS = time.Now().Add(-time.Minute).UnixMilli()
				}
				file := filepath.Join(t.TempDir(), "fixture.deb")
				if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				return file, nil
			}, metadata: func(*PkgPayload, string) (packageMetadata, error) {
				metadata := packageMetadata{Name: p.PkgName, Source: p.Inventory.Source, Version: p.TargetVersion, Architecture: p.Inventory.Architecture}
				switch scenario {
				case "wrong-name":
					metadata.Name = "other"
				case "wrong-source":
					metadata.Source = "rpm"
				case "wrong-version":
					metadata.Version = "1.9"
				case "wrong-architecture":
					metadata.Architecture = "i386"
				case "unreadable-package":
					return packageMetadata{}, errors.New("bad header")
				}
				return metadata, nil
			}, install: func(*PkgPayload, string, func(string, ...any)) (bool, error) {
				installs++
				if scenario == "installation-failed" {
					return false, errors.New("failed")
				}
				return false, nil
			}}
			result := fixPackageWithOperations(&pb.FixItem{RefId: "1", Payload: value}, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), ops)
			if scenario == "complete" {
				if !result.GetSuccess() || !result.GetVerified() || queries != 3 || downloads != 1 || installs != 1 {
					t.Fatal("complete verification did not succeed")
				}
				return
			}
			if result.GetSuccess() || result.GetVerified() {
				t.Fatal("uncertain repair marked successful")
			}
			if scenario == "identity-before-download" && downloads != 0 {
				t.Fatal("stale installation downloaded a package")
			}
			if !strings.Contains(scenario, "after-install") && scenario != "installation-failed" && installs != 0 {
				t.Fatal("rejected metadata or identity reached installer")
			}
		})
	}
}

func TestDownloadPatchPreservesPackageExtensionAndChecksTLSAndChecksum(t *testing.T) {
	body := []byte("fixture package")
	sum := sha256.Sum256(body)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "fixture-secret" {
			t.Error("download token was not retained")
		}
		w.Write(body)
	}))
	defer server.Close()
	workDir := t.TempDir()
	certDir := filepath.Join(workDir, "certs")
	if err := os.Mkdir(certDir, 0700); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(certDir, "ca.crt"), ca, 0600); err != nil {
		t.Fatal(err)
	}
	for _, repoType := range []string{"deb", "rpm", "msu"} {
		t.Run(repoType, func(t *testing.T) {
			payload := &PkgPayload{RepoType: repoType,
				DispatchDeadlineMS: time.Now().Add(time.Minute).UnixMilli(),
				DownloadURL:        server.URL + "/api/fix/patches/download?filename=test." + repoType + "&token=fixture-secret",
				Sha256:             hex.EncodeToString(sum[:])}
			name, err := downloadPatch(workDir, payload)
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(name)
			if filepath.Ext(name) != "."+repoType || strings.Contains(name, "fixture-secret") {
				t.Fatalf("invalid package filename: %q", name)
			}
			got, err := os.ReadFile(name)
			if err != nil || string(got) != string(body) {
				t.Fatalf("downloaded body = %q, error = %v", got, err)
			}
			payload.Sha256 = strings.Repeat("0", 64)
			if name, err := downloadPatch(workDir, payload); err == nil || name != "" {
				t.Fatalf("corrupt package accepted: name=%q error=%v", name, err)
			}
			if name, err := downloadPatch(t.TempDir(), payload); err == nil || name != "" {
				t.Fatalf("download without platform CA accepted: name=%q error=%v", name, err)
			}
		})
	}
}

func TestParsePkgPayloadRejectsUnsupportedPackageType(t *testing.T) {
	_, err := parsePkgPayload(`{"repo_type":"../sh","pkg_name":"openssl","target_version":"3","download_url":"https://console.example.test/package","sha256":"abc123"}`)
	if err == nil {
		t.Fatal("unsupported package type was accepted")
	}
}
