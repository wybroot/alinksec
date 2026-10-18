//go:build linux

package scan

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Uses the independently installed native libcrypt to create public synthetic
// hashes. No real account, authentication service or system file is changed.
func TestNativeWeakPasswordHashes(t *testing.T) {
	if os.Getenv("ALINKSEC_WEAKPWD_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit native acceptance only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native fixture must exercise root-owned identity files")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-c", `import ctypes,ctypes.util,json
lib=ctypes.CDLL(ctypes.util.find_library('crypt'));lib.crypt.argtypes=[ctypes.c_char_p,ctypes.c_char_p];lib.crypt.restype=ctypes.c_char_p
settings=['$1$salt1234$','$5$rounds=1000$salt1234$','$6$rounds=1000$salt1234$','$2b$04$abcdefghijklmnopqrstuu','$y$j9T$AAt9R641xPvCI9nXw1HHW/']
out=[]
for salt in settings:
 h=lib.crypt(b'password',salt.encode())
 if not h or h.startswith(b'*'):raise RuntimeError('required native algorithm missing')
 out.append(h.decode())
print(json.dumps(out))`)
	data, err := cmd.Output()
	if err != nil {
		t.Fatal("native libcrypt fixture failed", err)
	}
	var hashes []string
	if json.Unmarshal(data, &hashes) != nil || len(hashes) != 5 {
		t.Fatal("native fixture incomplete")
	}
	var checks []string
	for i, hash := range hashes {
		alg, e := hashAlgorithm(hash)
		if e != nil {
			t.Fatalf("native format %d rejected", i)
		}
		hit, e := checkCandidate(hash, "password", alg)
		if e != nil || !hit {
			t.Fatalf("native %s positive mismatch", alg)
		}
		hit, e = checkCandidate(hash, "public-negative-fixture", alg)
		if e != nil || hit {
			t.Fatalf("native %s negative mismatch", alg)
		}
		p, s := identities(t, hash)
		findings, c := scanLocalPasswords(ctx, p, s, nil)
		found := false
		for _, f := range findings {
			if f.Type == "system_weak" {
				found = true
			}
			if f.Password != "" {
				t.Fatal("credential leak")
			}
		}
		if c.Status != "complete" || c.AccountsChecked != 1 || c.CandidatesTested != 2 || !found {
			t.Fatalf("native %s full engine coverage failed: %v", alg, c)
		}
		evidence, _ := json.Marshal(struct {
			Findings any
			Coverage any
		}{findings, c})
		if strings.Contains(string(evidence), hash) {
			t.Fatal("hash leaked")
		}
		checks = append(checks, alg+"_native_positive_negative_and_scan")
	}
	path := os.Getenv("ALINKSEC_WEAKPWD_EVIDENCE_FILE")
	if path == "" {
		t.Fatal("evidence output required")
	}
	result := map[string]any{"passed": true, "platform": runtime.GOOS + "-" + runtime.GOARCH, "dictionary_version": DictionaryVersion, "dictionary_sha256": DictionarySHA256, "checks": checks, "scope": "native_libcrypt_and_protected_synthetic_local_files"}
	b, _ := json.MarshalIndent(result, "", "  ")
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(b, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
