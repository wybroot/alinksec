//go:build windows || linux

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func upgradeSnapshotDigest(path string) ([32]byte, error) {
	var digest [32]byte
	f, err := openUpgradeSnapshot(path)
	if err != nil {
		return digest, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (64<<20)+1))
	if err != nil {
		return digest, err
	}
	if n > 64<<20 {
		return digest, fmt.Errorf("upgrade snapshot exceeds 64 MiB")
	}
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func TestUpgradeObserverAllowsCandidateReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "候选 Agent with spaces.exe")
	if err := os.WriteFile(path, []byte("original"), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := openUpgradeSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal("observer blocked upgrade:", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil || string(data) != "original" {
		t.Fatalf("held snapshot changed: %q %v", data, err)
	}
	current, err := upgradeSnapshotDigest(path)
	if err != nil || current != sha256.Sum256([]byte("replacement")) {
		t.Fatal("observer did not see replacement", err)
	}
}
