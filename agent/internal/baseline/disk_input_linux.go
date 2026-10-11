//go:build linux

package baseline

import (
	"fmt"
	"io"
)

// Keep literal bytes for APIs whose grammar does not normalize CRLF, comments
// or whitespace. The shared reader retains descriptors and guards replacement.
func boundedDiskInput(r *pamRead, path string) ([]byte, error) {
	f, err := r.open(path, false)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	r.bytes += len(raw)
	if err != nil || len(raw) > 64*1024 || r.budget() != nil {
		return nil, fmt.Errorf("bounded disk input unavailable")
	}
	return raw, nil
}
