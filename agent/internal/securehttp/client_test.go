package securehttp

import "testing"

func TestValidateURLRequiresHTTPS(t *testing.T) {
	if _, err := ValidateURL("http://server.example/file"); err == nil {
		t.Fatal("HTTP URL was accepted")
	}
	if _, err := ValidateURL("https://server.example/file"); err != nil {
		t.Fatalf("HTTPS URL rejected: %v", err)
	}
}
