//go:build linux

package scan

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Public synthetic fixture from the independent crypt(3) reference vectors.
const md5Password = "$1$ip0xp41O$7DHwMihQRmDjn2tiJ17mw."

func identities(t *testing.T, hashes ...string) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("protected identity fixtures require root ownership")
	}
	root := t.TempDir()
	p, s := filepath.Join(root, "passwd"), filepath.Join(root, "shadow")
	var passwd, shadow strings.Builder
	for i, h := range hashes {
		name := []string{"root", "user", "locked", "service", "extra"}[i]
		passwd.WriteString(name + ":x:1000:1000::/tmp:/bin/sh\n")
		shadow.WriteString(name + ":" + h + ":20000:0:99999:7:::\n")
	}
	if err := os.WriteFile(p, []byte(passwd.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s, []byte(shadow.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return p, s
}
func TestDictionaryAndHashBoundaries(t *testing.T) {
	if len(dictionary) != 100 || len(DictionarySHA256) != 64 {
		t.Fatal("dictionary identity")
	}
	seen := map[string]bool{}
	for _, w := range dictionary {
		if seen[w] || w == "" {
			t.Fatal("invalid dictionary")
		}
		seen[w] = true
	}
	for _, h := range []string{"$6$rounds=999999999$salt$" + strings.Repeat("a", 86), "$y$jET$salt$" + strings.Repeat("a", 43), "$2b$31$" + strings.Repeat("a", 53), "$argon2id$unbounded", "$6$rounds=99999999999999999999999$x$x", "$1$x$bad"} {
		if _, err := hashAlgorithm(h); err == nil {
			t.Fatal("accepted unsupported or invalid cost")
		}
	}
	a, e := hashAlgorithm(md5Password)
	if e != nil || a != "md5crypt" {
		t.Fatal("known crypt format")
	}
	ok, e := checkCandidate(md5Password, "password", a)
	if e != nil || !ok {
		t.Fatal("known reference vector")
	}
	ok, e = checkCandidate(md5Password, "wrong", a)
	if e != nil || ok {
		t.Fatal("negative reference vector")
	}
}
func TestOfflineCoverageRedactsAndExcludes(t *testing.T) {
	p, s := identities(t, md5Password, "", "!"+md5Password, "*")
	findings, c := scanLocalPasswords(context.Background(), p, s, nil)
	if c.Status != "complete" || c.AccountsSeen != 4 || c.AccountsChecked != 2 || c.AccountsExcluded != 2 || c.CandidatesTested != 2 {
		t.Fatalf("coverage: %v", c)
	}
	kinds := map[string]bool{}
	for _, f := range findings {
		kinds[f.Type] = true
		if f.Password != "" {
			t.Fatal("credential leaked")
		}
	}
	if !kinds["system_weak"] || !kinds["system_empty"] {
		t.Fatal("missing findings")
	}
	data, _ := json.Marshal(findings)
	if strings.Contains(string(data), md5Password) || strings.Contains(string(data), "password") {
		t.Fatal("secret in findings")
	}
}
func TestOfflineUnknownHashAndCancellationAreNotPasses(t *testing.T) {
	p, s := identities(t, "$unknown$hash", md5Password)
	_, c := scanLocalPasswords(context.Background(), p, s, nil)
	if c.Status != "partial" || c.AccountsUnsupported != 1 || c.AccountsChecked != 1 {
		t.Fatal(c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, c = scanLocalPasswords(ctx, p, s, nil)
	if c.Status != "partial" || c.AccountsFailed != 2 || c.CandidatesTested != 0 {
		t.Fatal(c)
	}
}
func TestOfflineFileBoundariesAndChangedSnapshot(t *testing.T) {
	p, s := identities(t, md5Password)
	data, err := os.ReadFile(s)
	if err != nil {
		t.Fatal(err)
	}
	_, c := scanLocalPasswords(context.Background(), p, s, func(context.Context) error { return os.WriteFile(s, append(data, '\n'), 0600) })
	if c.Status != "failed" || !strings.Contains(strings.Join(c.Issues, ","), "identity_changed") {
		t.Fatal(c)
	}
	if err := os.Remove(s); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p, s); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentity(s); err == nil {
		t.Fatal("symlink followed")
	}
	os.Remove(s)
	if err := unix.Mkfifo(s, 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := readIdentity(s); err == nil || time.Since(start) > time.Second {
		t.Fatal("FIFO read or blocked")
	}
	os.Remove(s)
	os.WriteFile(s, data, 0666)
	os.Chmod(s, 0666)
	if _, err := readIdentity(s); err == nil {
		t.Fatal("writable identity accepted")
	}
}
func TestIdentityParsingRejectsAmbiguity(t *testing.T) {
	p := []byte("user:x:1000:1000::/tmp:/bin/sh\n")
	s := []byte("user:!:20000:0:99999:7:::\n")
	for _, pair := range [][2][]byte{{append(append([]byte{}, p...), p...), s}, {p, append(append([]byte{}, s...), s...)}, {p, []byte("other:!:20000:0:99999:7:::\n")}, {[]byte("user:x:bad:1000::/tmp:/bin/sh\n"), s}, {p, []byte("user:!:bad:0:99999:7:::\n")}} {
		if _, e := parseIdentities(pair[0], pair[1]); e == nil {
			t.Fatal("ambiguous input accepted")
		}
	}
}
