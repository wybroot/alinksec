package virusscan

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetirementReleaseClearsPreviouslyLoadedHash(t *testing.T) {
	work := t.TempDir()
	hash := strings.Repeat("b", 64)
	for _, release := range []struct{ version, hashes string }{{"original", hash + " Fixture 3\n"}, {"retirement", ""}} {
		file := filepath.Join(work, release.version+".zip")
		out, err := os.Create(file)
		if err != nil {
			t.Fatal(err)
		}
		writer := zip.NewWriter(out)
		for name, body := range map[string]string{"manifest.json": fmt.Sprintf(`{"db_version":%q}`, release.version), "hashes.txt": release.hashes, "rules.json": `{"rules":[]}`} {
			entry, err := writer.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		bytes, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := InstallDB(work, file, fmt.Sprintf("%x", sha256.Sum256(bytes))); err != nil {
			t.Fatal(err)
		}
		db := ReloadDB(work)
		_, found := db.Lookup(hash)
		if found != (release.version == "original") || db.Version != release.version {
			t.Fatal("retirement did not clear the installed and loaded hash")
		}
	}
}
