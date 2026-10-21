package virusscan

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func signatureZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, body := range entries {
		f, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func digestBytes(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func fixtureIdentity(entries map[string]string) string {
	return digestBytes([]byte(digestBytes([]byte(entries["manifest.json"])) + digestBytes([]byte(entries["hashes.txt"])) + digestBytes([]byte(entries["rules.json"]))))
}
func signatureServer(t *testing.T, work string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	if err := os.MkdirAll(filepath.Join(work, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "certs/ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return server
}
func installFixture(t *testing.T, work string, data []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "full.zip")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := InstallDB(work, p, digestBytes(data)); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureDeltaTLSFallbackAndExactContent(t *testing.T) {
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	base := map[string]string{"manifest.json": `{"db_version":"base","hash_count":2,"rule_count":1}`, "hashes.txt": a + " Old 3\n" + b + " Remove 4\n", "rules.json": `{"rules":[{"name":"OldRule","strings":[{"value":"old"}]}]}`}
	target := map[string]string{"manifest.json": `{"db_version":"target","hash_count":2,"rule_count":1}`, "hashes.txt": a + " Changed 5\n" + c + " Added 4\n", "rules.json": `{"rules":[{"name":"NewRule","strings":[{"value":"new"}]}]}`}
	m := deltaManifest{Contract: 1, BaseVersion: "base", BaseContent: fixtureIdentity(base), TargetVersion: "target", TargetContent: fixtureIdentity(target)}
	metadata, _ := json.Marshal(m)
	patch := map[string]string{"delta.json": string(metadata), "manifest.json": target["manifest.json"], "hashes.txt": target["hashes.txt"], "removed.txt": b + "\n", "rules.json": target["rules.json"]}
	baseZip, full, delta := signatureZip(t, base), signatureZip(t, target), signatureZip(t, patch)
	for _, scenario := range []string{"delta", "corrupt-base", "bad-delta", "bad-target", "bad-full", "missing-base", "same-version-corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			work := t.TempDir()
			installFixture(t, work, baseZip)
			if scenario == "corrupt-base" {
				os.WriteFile(filepath.Join(DBDir(work), "hashes.txt"), []byte(a+" Tampered 3\n"+b+" Remove 4\n"), 0600)
			}
			if scenario == "missing-base" {
				os.RemoveAll(DBDir(work))
			}
			if scenario == "same-version-corrupt" {
				installFixture(t, work, full)
				os.WriteFile(filepath.Join(DBDir(work), "hashes.txt"), []byte(a+" Tampered 3\n"+c+" Added 4\n"), 0600)
			}
			before := parseDB(DBDir(work))
			paths := []string{}
			var pathsMu sync.Mutex
			getPaths := func() []string { pathsMu.Lock(); defer pathsMu.Unlock(); return append([]string(nil), paths...) }
			server := signatureServer(t, work, func(w http.ResponseWriter, r *http.Request) {
				pathsMu.Lock()
				paths = append(paths, r.URL.Path)
				pathsMu.Unlock()
				data := full
				if r.URL.Path == "/delta" {
					data = delta
					if scenario == "bad-delta" {
						data = []byte("corrupt")
					}
				}
				if scenario == "bad-full" {
					data = []byte("corrupt")
				}
				w.Write(data)
			})
			spec := UpdateSpec{Version: "target", URL: server.URL + "/full", SHA256: digestBytes(full), DeltaURL: server.URL + "/delta", DeltaSHA256: digestBytes(delta), BaseVersion: "base", BaseContent: m.BaseContent, Content: m.TargetContent}
			if scenario == "bad-target" {
				spec.Content = strings.Repeat("0", 64)
			}
			receipt, err := UpdateRelease(context.Background(), work, spec)
			if scenario == "bad-target" || scenario == "bad-full" {
				if err == nil || !reflect.DeepEqual(before, parseDB(DBDir(work))) {
					t.Fatal("invalid candidate changed previous database", receipt, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			db := ReloadDB(work)
			digest, err := contentDigest(DBDir(work))
			if err != nil || !db.Valid || db.Version != "target" || digest != m.TargetContent || len(db.hashes) != 2 || db.hashes[a].Name != "Changed" || db.hashes[c].Name != "Added" || db.rules[0].Name != "NewRule" {
				t.Fatal("target not reconstructed", receipt, digest, err)
			}
			if scenario == "delta" && (receipt.Mode != "delta" || !reflect.DeepEqual(getPaths(), []string{"/delta"})) {
				t.Fatal(receipt, getPaths())
			}
			if scenario != "delta" && receipt.Mode != "full" {
				t.Fatal(receipt, getPaths())
			}
			count := len(getPaths())
			replay, err := UpdateRelease(context.Background(), work, spec)
			if err != nil || replay.Mode != "already-current" || replay.Downloaded != 0 || len(getPaths()) != count {
				t.Fatal("replay downloaded again", replay, err)
			}
			left, _ := filepath.Glob(filepath.Join(work, "virus/pkg-*.tmp"))
			if len(left) != 0 {
				t.Fatal("temporary packages retained", left)
			}
		})
	}
}

func TestSignatureRecoveryAfterInterruptedDirectorySwitch(t *testing.T) {
	work := t.TempDir()
	base := map[string]string{"manifest.json": `{"db_version":"recover"}`, "hashes.txt": strings.Repeat("a", 64) + " Known 4\n"}
	installFixture(t, work, signatureZip(t, base))
	ReloadDB(work)
	if err := os.Rename(DBDir(work), DBDir(work)+".old"); err != nil {
		t.Fatal(err)
	}
	if LocalVersion(work) != "recover" || !ReloadDB(work).Valid {
		t.Fatal("interrupted rename did not recover")
	}
	if _, err := os.Stat(DBDir(work) + ".old"); !os.IsNotExist(err) {
		t.Fatal("recovery left stale backup")
	}
	if err := os.Rename(DBDir(work), DBDir(work)+".old"); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(DBDir(work), 0700)
	os.WriteFile(filepath.Join(DBDir(work), "manifest.json"), []byte(`{"db_version":"broken"}`), 0600)
	if LocalVersion(work) != "recover" {
		t.Fatal("invalid target displaced valid backup")
	}
}

func TestSignatureDownloadBoundsAndCancellation(t *testing.T) {
	work := t.TempDir()
	server := signatureServer(t, work, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(maxPackageBytes+1))
		w.WriteHeader(200)
	})
	if _, _, err := downloadPackage(context.Background(), work, server.URL); err == nil {
		t.Fatal("oversized response accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := downloadPackage(ctx, work, server.URL); err == nil {
		t.Fatal("cancelled download accepted")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := copyLimited(ctx, &bytes.Buffer{}, bytes.NewReader(make([]byte, 1<<20))); err == nil {
		t.Fatal("rate pacing ignored cancellation")
	}
}

func TestMalformedDeltaNeverChangesLiveDatabase(t *testing.T) {
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	base := map[string]string{"manifest.json": `{"db_version":"base","hash_count":2,"rule_count":0}`, "hashes.txt": b + " First 3\n" + c + " Second 3\n", "rules.json": `{"rules":[]}`}
	target := map[string]string{"manifest.json": `{"db_version":"target","hash_count":2,"rule_count":0}`, "hashes.txt": a + " Added 4\n" + c + " Changed 5\n", "rules.json": `{"rules":[]}`}
	spec := UpdateSpec{Version: "target", BaseVersion: "base", BaseContent: fixtureIdentity(base), Content: fixtureIdentity(target)}
	meta, _ := json.Marshal(deltaManifest{Contract: 1, BaseVersion: "base", BaseContent: spec.BaseContent, TargetVersion: "target", TargetContent: spec.Content})
	for _, scenario := range []string{"unknown-removal", "duplicate-removal", "overlap-after-earlier-update", "unordered-updates", "duplicate-updates", "missing-member", "illegal-member", "invalid-rules", "oversize-rules", "wrong-metadata", "wrong-count"} {
		t.Run(scenario, func(t *testing.T) {
			work := t.TempDir()
			installFixture(t, work, signatureZip(t, base))
			before := parseDB(DBDir(work))
			patch := map[string]string{"delta.json": string(meta), "manifest.json": target["manifest.json"], "hashes.txt": target["hashes.txt"], "removed.txt": b + "\n", "rules.json": target["rules.json"]}
			switch scenario {
			case "unknown-removal":
				patch["removed.txt"] = strings.Repeat("d", 64) + "\n"
			case "duplicate-removal":
				patch["removed.txt"] = b + "\n" + b + "\n"
			case "overlap-after-earlier-update":
				patch["removed.txt"] = b + "\n" + c + "\n"
			case "unordered-updates":
				patch["hashes.txt"] = c + " Changed 5\n" + a + " Added 4\n"
			case "duplicate-updates":
				patch["hashes.txt"] = a + " Added 4\n" + a + " Added 4\n" + c + " Changed 5\n"
			case "missing-member":
				delete(patch, "rules.json")
			case "illegal-member":
				patch["../outside"] = "unexpected"
			case "invalid-rules":
				patch["rules.json"] = `{"rules":[{"name":"bad","strings":[]}]}`
			case "oversize-rules":
				patch["rules.json"] = strings.Repeat("x", int(maxRuleBytes)+1)
			case "wrong-metadata":
				patch["delta.json"] = `{"contract":99}`
			case "wrong-count":
				patch["manifest.json"] = `{"db_version":"target","hash_count":100,"rule_count":0}`
			}
			data := signatureZip(t, patch)
			file := filepath.Join(t.TempDir(), "delta.zip")
			os.WriteFile(file, data, 0600)
			if err := installDB(work, file, digestBytes(data), &spec, true); err == nil {
				t.Fatal("malformed delta accepted")
			}
			if !reflect.DeepEqual(before, parseDB(DBDir(work))) || LocalVersion(work) != "base" {
				t.Fatal("malformed delta changed live library")
			}
		})
	}
}
