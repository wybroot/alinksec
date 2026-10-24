//go:build windows

package virusscan

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSignatureReaderAllowsDirectoryRetirement(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "数据库 with spaces")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hashes.txt"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	f, parent, err := openRegular(filepath.Join(dir, "hashes.txt"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer parent.Close()
	identity := parentIdentity(parent)
	if identity == "" {
		t.Fatal("missing pinned directory identity")
	}
	// Hold both descriptors across the real switch; retries would hide a broken
	// sharing contract. Replacement bytes must not affect the old snapshot.
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal("retire with active reader:", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hashes.txt"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "original" || parentIdentity(parent) != identity {
		t.Fatalf("snapshot changed: %q %v", b, err)
	}
	old, err := openAt(parent, "hashes.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	b, err = io.ReadAll(old)
	if err != nil || string(b) != "original" {
		t.Fatalf("relative open escaped pinned parent: %q %v", b, err)
	}
	// Shared delete is independent of write sharing: a scanner still excludes
	// concurrent writes to its pinned signature file.
	writer, err := os.OpenFile(filepath.Join(dir+".old", "hashes.txt"), os.O_WRONLY, 0600)
	if err == nil {
		writer.Close()
		t.Fatal("pinned signature file allowed concurrent writes")
	}
}
