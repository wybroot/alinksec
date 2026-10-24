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
	// NTFS refuses directory rename while a descendant file is open, even
	// with shared delete. Finish the file read before retiring its parent.
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "original" {
		t.Fatalf("snapshot changed: %q %v", b, err)
	}
	writer, err := os.OpenFile(filepath.Join(dir, "hashes.txt"), os.O_WRONLY, 0600)
	if err == nil {
		writer.Close()
		t.Fatal("pinned signature file allowed concurrent writes")
	}
	if err := os.Rename(dir, dir+".old"); err == nil {
		t.Fatal("directory unexpectedly retired with an open descendant")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Keep the directory descriptor across retirement without retries. New
	// pathname bytes must never redirect relative opens from this old handle.
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal("retire with active reader:", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hashes.txt"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if parentIdentity(parent) != identity {
		t.Fatal("pinned directory identity changed")
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
	writer, err = os.OpenFile(filepath.Join(dir+".old", "hashes.txt"), os.O_WRONLY, 0600)
	if err == nil {
		writer.Close()
		t.Fatal("pinned signature file allowed concurrent writes")
	}
}
