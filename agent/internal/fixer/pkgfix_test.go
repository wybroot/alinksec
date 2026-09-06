package fixer

import "testing"

func TestParsePkgPayloadRequiresChecksum(t *testing.T) {
	_, err := parsePkgPayload(`{"pkg_name":"openssl","target_version":"3.0.0","download_url":"https://console.example.test/package"}`)
	if err == nil {
		t.Fatal("payload without sha256 was accepted")
	}
}

func TestParsePkgPayloadAcceptsCompletePackageMetadata(t *testing.T) {
	pkg, err := parsePkgPayload(`{"pkg_name":"openssl","target_version":"3.0.0","download_url":"https://console.example.test/package","sha256":"abc123"}`)
	if err != nil {
		t.Fatalf("parsePkgPayload() error = %v", err)
	}
	if pkg.Sha256 != "abc123" {
		t.Fatalf("Sha256 = %q, want abc123", pkg.Sha256)
	}
}
