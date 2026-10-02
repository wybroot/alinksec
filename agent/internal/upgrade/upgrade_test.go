package upgrade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifyPlatform(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPlatform(executable, runtime.GOOS, runtime.GOARCH); err != nil {
		t.Fatalf("native executable rejected: %v", err)
	}
	otherArch := "arm64"
	if runtime.GOARCH == otherArch {
		otherArch = "amd64"
	}
	if err := verifyPlatform(executable, runtime.GOOS, otherArch); err == nil {
		t.Fatal("accepted an executable for another architecture")
	}
	otherOS := "windows"
	if runtime.GOOS == otherOS {
		otherOS = "linux"
	}
	if err := verifyPlatform(executable, otherOS, runtime.GOARCH); err == nil {
		t.Fatal("accepted an executable for another operating system")
	}
}

func TestVerifyPlatformRejectsInvalidPackage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(path, []byte("not an executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPlatform(path, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("accepted an invalid upgrade package")
	}
}
