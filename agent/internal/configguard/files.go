package configguard

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

// Paths are kept lexical and absolute: resolving a link would silently bless
// its target. Every existing parent and the opened object are checked instead.
func absolute(path string) (string, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" && (len(p) < 3 || p[1] != ':' || strings.Contains(p[2:], ":")) {
		return "", fmt.Errorf("configuration requires a local drive path without alternate streams")
	}
	return filepath.Clean(p), nil
}

func realParents(path string) error {
	return parentDirectories(path, false)
}
func parentDirectories(path string, allowMissing bool) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if allowMissing && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !i.IsDir() || isLink(i) {
			return fmt.Errorf("configuration parent is not a real directory")
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// ReadFile never follows the final link or opens FIFOs/devices as configuration.
// The pre/open/post identity checks also reject replacement during a read.
func ReadFile(path string, limit int) ([]byte, error) {
	var err error
	path, err = absolute(path)
	if err != nil {
		return nil, err
	}
	if err := realParents(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || isLink(before) || before.Size() > int64(limit) {
		return nil, fmt.Errorf("unsafe configuration file")
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || !os.SameFile(before, i) {
		return nil, fmt.Errorf("configuration identity changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, fmt.Errorf("configuration read failed or exceeds limit")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(i, after) || after.Size() != i.Size() || !after.ModTime().Equal(i.ModTime()) {
		return nil, fmt.Errorf("configuration changed during read")
	}
	return b, nil
}

func writeAtomic(path string, b []byte) error {
	if err := realParents(path); err != nil {
		return err
	}
	if i, err := os.Lstat(path); err == nil {
		if !i.Mode().IsRegular() || isLink(i) {
			return fmt.Errorf("refusing to replace a special configuration file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := writableParent(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = protectFile(tmp); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return securestate.Replace(tmp, path)
}
