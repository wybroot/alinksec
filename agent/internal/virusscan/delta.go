package virusscan

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Content identity includes the exact manifest, hash and rule bytes, in that
// order. A missing optional rules.json has the digest of zero bytes.
func contentDigest(dir string) (string, error) {
	h := sha256.New()
	for _, name := range []string{"manifest.json", "hashes.txt", "rules.json"} {
		limit := maxExpandedBytes
		if name == "manifest.json" {
			limit = 64 << 10
		}
		if name == "rules.json" {
			limit = maxRuleBytes
		}
		part := sha256.New()
		f, parent, err := openRegular(filepath.Join(dir, name), false)
		if os.IsNotExist(err) && name == "rules.json" {
			fmt.Fprintf(h, "%x", part.Sum(nil))
			continue
		}
		if err != nil {
			return "", err
		}
		n, err := io.Copy(part, io.LimitReader(f, limit+1))
		f.Close()
		parent.Close()
		if err != nil {
			return "", err
		}
		if n > limit {
			return "", fmt.Errorf("signature member exceeds limit")
		}
		fmt.Fprintf(h, "%x", part.Sum(nil))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type deltaManifest struct {
	Contract      uint32 `json:"contract"`
	BaseVersion   string `json:"base_version"`
	BaseContent   string `json:"base_content_sha256"`
	TargetVersion string `json:"target_version"`
	TargetContent string `json:"target_content_sha256"`
}

// expandDelta operates only on private staging data. The live and cached maps
// remain untouched until the complete target passes the normal DB validator.
func expandDelta(dbDir, tmp string, spec UpdateSpec) error {
	data, err := boundedFile(filepath.Join(tmp, "delta.json"), 64<<10)
	if err != nil {
		return err
	}
	var m deltaManifest
	if json.Unmarshal(data, &m) != nil || m.Contract != 1 || m.BaseVersion != spec.BaseVersion || m.BaseContent != spec.BaseContent || m.TargetVersion != spec.Version || m.TargetContent != spec.Content {
		return fmt.Errorf("delta identity mismatch")
	}
	manifest, err := boundedFile(filepath.Join(dbDir, "manifest.json"), 64<<10)
	var base dbManifest
	digest, digestErr := contentDigest(dbDir)
	if err != nil || json.Unmarshal(manifest, &base) != nil || base.DbVersion != spec.BaseVersion || digestErr != nil || digest != spec.BaseContent {
		return fmt.Errorf("delta base mismatch")
	}
	old, err := openSortedHashes(filepath.Join(dbDir, "hashes.txt"), false)
	if err != nil {
		return err
	}
	defer old.close()
	updates, err := openSortedHashes(filepath.Join(tmp, "hashes.txt"), false)
	if err != nil {
		return err
	}
	defer updates.close()
	removed, err := openSortedHashes(filepath.Join(tmp, "removed.txt"), true)
	if err != nil {
		return err
	}
	defer removed.close()
	next := filepath.Join(tmp, "hashes.rebuilt")
	out, err := os.OpenFile(next, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	writer := bufio.NewWriter(out)
	a, b, r := old.next(), updates.next(), removed.next()
	count, size := 0, int64(0)
	write := func(line string) error {
		count++
		size += int64(len(line) + 1)
		if count > maxHashEntries || size > maxExpandedBytes {
			return fmt.Errorf("delta exceeds target capacity")
		}
		_, err := writer.WriteString(line + "\n")
		return err
	}
	for a != "" || b != "" {
		if r != "" && (a == "" || r < a[:64]) {
			return fmt.Errorf("delta removes an unknown hash")
		}
		if a == "" || b != "" && b[:64] < a[:64] {
			if err = write(b); err != nil {
				return err
			}
			b = updates.next()
			continue
		}
		if a != "" && r == a[:64] {
			if b != "" && b[:64] == r {
				return fmt.Errorf("delta removal overlaps update")
			}
			a, r = old.next(), removed.next()
			continue
		}
		if b != "" && a[:64] == b[:64] {
			if err = write(b); err != nil {
				return err
			}
			a, b = old.next(), updates.next()
		} else {
			if err = write(a); err != nil {
				return err
			}
			a = old.next()
		}
	}
	if r != "" {
		return fmt.Errorf("delta removes an unknown hash")
	}
	for _, input := range []*sortedHashes{old, updates, removed} {
		if input.err != nil {
			return input.err
		}
	}
	if err = writer.Flush(); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	// Windows requires the source handles closed before replacing staging files.
	updates.close()
	removed.close()
	if err = os.Rename(next, filepath.Join(tmp, "hashes.txt")); err != nil {
		return err
	}
	for _, name := range []string{"delta.json", "removed.txt"} {
		if err := os.Remove(filepath.Join(tmp, name)); err != nil {
			return err
		}
	}
	return nil
}

// Canonical sorted streams bound reconstruction memory independently of inventory
// size and reject duplicate, unordered, overlapping or nonexistent operations.
type sortedHashes struct {
	file, parent *os.File
	scanner      *bufio.Scanner
	previous     string
	count        int
	removals     bool
	err          error
}

func openSortedHashes(path string, removals bool) (*sortedHashes, error) {
	f, parent, err := openRegular(path, false)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4096)
	return &sortedHashes{file: f, parent: parent, scanner: scanner, removals: removals}, nil
}
func (s *sortedHashes) close() { s.file.Close(); s.parent.Close() }
func (s *sortedHashes) next() string {
	if s.err != nil {
		return ""
	}
	if !s.scanner.Scan() {
		s.err = s.scanner.Err()
		return ""
	}
	line := s.scanner.Text()
	key := line
	valid := true
	if !s.removals {
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			valid = false
		} else {
			key = parts[0]
			severity, err := strconv.Atoi(parts[2])
			valid = err == nil && severity >= 1 && severity <= 5 && strconv.Itoa(severity) == parts[2] && parts[1] != "" && utf8.ValidString(parts[1]) && utf8.RuneCountInString(parts[1]) <= 255 && !strings.ContainsAny(parts[1], "\t\r\n")
		}
	}
	s.count++
	if !valid || !validDigest(key) || key <= s.previous || s.count > maxHashEntries {
		s.err = fmt.Errorf("invalid or unordered delta hash stream")
		return ""
	}
	s.previous = key
	return line
}

// Called under installMu. A crash between the two directory renames leaves a
// validated previous directory available for recovery before any new read.
func recoverDB(workDir string) error {
	dir := DBDir(workDir)
	old := dir + ".old"
	if _, err := os.Lstat(old); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if parseDB(dir).Valid {
		// A locked historical file must not disable a validated current library.
		_ = os.RemoveAll(old)
		return nil
	}
	if !parseDB(old).Valid {
		return fmt.Errorf("signature recovery has no valid database")
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.Rename(old, dir)
}
