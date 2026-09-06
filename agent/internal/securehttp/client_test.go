package securehttp

import "testing"

func TestValidateURLRequiresHTTPS(t *testing.T) {
	for _, rawURL := range []string{
		"http://server.example/file",
		"/relative/file",
		"https://user:secret@server.example/file",
	} {
		if _, err := ValidateURL(rawURL); err == nil {
			t.Fatalf("unsafe URL was accepted: %s", rawURL)
		}
	}
	if _, err := ValidateURL("https://server.example/file"); err != nil {
		t.Fatalf("HTTPS URL rejected: %v", err)
	}
}
