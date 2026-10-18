// Package securestate provides bounded, private, atomic records and process locks
// for recovery services that must coordinate with the Agent across restarts.
package securestate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("recovery directory is not a real directory")
	}
	return protectDirectory(path)
}

func ReadJSON(path string, value any) error {
	return ReadJSONLimit(path, value, 65536)
}

// ReadJSONLimit admits larger bounded journals without relaxing recovery records.
func ReadJSONLimit(path string, value any, limit int64) error {
	if limit < 1 || limit > 4<<20 {
		return fmt.Errorf("invalid record limit")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return fmt.Errorf("invalid recovery record")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, limit+1))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing recovery record data")
	}
	return nil
}

func WriteJSON(path string, value any) error {
	return WriteJSONLimit(path, value, 65536)
}

func WriteJSONLimit(path string, value any, limit int) error {
	if limit < 1 || limit > 4<<20 {
		return fmt.Errorf("invalid record limit")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(b) > limit {
		return fmt.Errorf("recovery record exceeds %d bytes", limit)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".record-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return Replace(tmp, path)
}
