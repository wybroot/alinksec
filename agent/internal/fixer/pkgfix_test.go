package fixer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePkgPayloadRequiresChecksum(t *testing.T) {
	_, err := parsePkgPayload(`{"pkg_name":"openssl","target_version":"3.0.0","download_url":"https://console.example.test/package"}`)
	if err == nil {
		t.Fatal("payload without sha256 was accepted")
	}
}

func TestParsePkgPayloadAcceptsCompletePackageMetadata(t *testing.T) {
	pkg, err := parsePkgPayload(`{"repo_type":"deb","pkg_name":"openssl","target_version":"3.0.0","download_url":"https://console.example.test/package","sha256":"abc123"}`)
	if err != nil {
		t.Fatalf("parsePkgPayload() error = %v", err)
	}
	if pkg.Sha256 != "abc123" {
		t.Fatalf("Sha256 = %q, want abc123", pkg.Sha256)
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
				DownloadURL: server.URL + "/api/fix/patches/download?filename=test." + repoType + "&token=fixture-secret",
				Sha256:      hex.EncodeToString(sum[:])}
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
