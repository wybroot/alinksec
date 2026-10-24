// Package logcollect tails fixed Linux authentication log files. Windows shares
// windowslogin's native Security reader. Collection notices are marked metadata.
package logcollect

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
)

const (
	maxLineBytes  = 16 << 10
	maxBatchLines = 100
	maxPollBytes  = 256 << 10
	stateFile     = "logtail.state.json"
)

type fileState struct {
	Identity   string `json:"identity"`
	Generation string `json:"generation"`
	Offset     int64  `json:"offset"`
	Start      int64  `json:"start"`
	Prefix     []byte `json:"prefix,omitempty"`
	Total      int64  `json:"total"`
	EndsCR     bool   `json:"ends_cr,omitempty"`
	Observed   int64  `json:"observed"`
	Issue      string `json:"issue"`
	NoticeSeq  uint64 `json:"notice_seq"`
}
type stateJSON struct {
	Version int                  `json:"version"`
	Files   map[string]fileState `json:"files"`
}
type Collector struct {
	log          *slog.Logger
	statePath    string
	mu           sync.Mutex
	files        map[string]fileState
	stateInvalid bool
	send         func(string, []*pb.LogLine) bool
}

func New(workDir string, log *slog.Logger, send func(string, []*pb.LogLine) bool) *Collector {
	c := &Collector{log: log, statePath: filepath.Join(workDir, stateFile), files: map[string]fileState{}, send: send}
	c.loadState()
	return c
}
func (c *Collector) Run(ctx context.Context) {
	tk := time.NewTicker(pollInterval())
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			c.pollOnce()
		}
	}
}
func digest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func newGeneration() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func (c *Collector) notice(path, source, issue string, s *fileState) bool {
	if s.Issue == issue {
		return true
	}
	at := time.Now().UnixMilli()
	seq := s.NoticeSeq + 1
	line := &pb.LogLine{Ts: at, Content: "Log collection status: " + issue, Fields: map[string]string{
		"record_kind": "collection_status", "timestamp_kind": "observed", "status": issue, "path": path,
		"source_event_id": digest(fmt.Sprintf("notice\x00%s\x00%s\x00%d\x00%d\x00%s", path, s.Generation, seq, s.Offset, issue)),
	}}
	if !c.send(source, []*pb.LogLine{line}) {
		return false
	}
	s.Issue = issue
	s.NoticeSeq = seq
	return true
}

// A bounded fragment is persisted even without a newline. Failed queue admission
// keeps the previous cursor so the same immutable source event is retried.
func (c *Collector) tailFile(path, source string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.files[path]
	s := current
	s.Prefix = append([]byte(nil), s.Prefix...)
	if c.stateInvalid {
		if c.notice(path, source, "cursor_invalid", &s) {
			c.files[path] = s
		}
		return
	}
	f, err := openLog(path)
	if err != nil {
		issue := "unreadable"
		if os.IsNotExist(err) {
			issue = "missing"
		}
		if c.notice(path, source, issue, &s) {
			c.files[path] = s
			c.saveState()
		}
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		if c.notice(path, source, "not_regular", &s) {
			c.files[path] = s
			c.saveState()
		}
		return
	}
	identity := fileIdentity(st)
	replaced := s.Identity != "" && identity != s.Identity
	truncated := st.Size() < s.Offset
	if s.Generation == "" || replaced || truncated {
		if replaced || truncated {
			if !c.notice(path, source, "rotation_gap_possible", &s) {
				return
			}
			s.Offset = 0
			s.Start = 0
			s.Prefix = nil
			s.Total = 0
			s.EndsCR = false
			s.Observed = 0
		}
		s.Identity = identity
		s.Generation = newGeneration()
		c.files[path] = s
		if !c.saveState() {
			c.files[path] = current
			return
		}
	}
	if s.Issue != "reading" {
		if !c.notice(path, source, "reading", &s) {
			return
		}
	}
	if _, err = f.Seek(s.Offset, io.SeekStart); err != nil {
		return
	}
	reader := bufio.NewReaderSize(f, 4096)
	var batch []*pb.LogLine
	readBytes := 0
	batchBytes := 0
	for readBytes < maxPollBytes && len(batch) < maxBatchLines && batchBytes < 256<<10 {
		part, readErr := reader.ReadSlice('\n')
		if len(part) > 0 {
			if s.Total == 0 {
				s.Start = s.Offset
				s.Observed = time.Now().UnixMilli()
				s.EndsCR = false
			}
			s.Offset += int64(len(part))
			readBytes += len(part)
			complete := part[len(part)-1] == '\n'
			body := part
			if complete {
				body = body[:len(body)-1]
			}
			if remaining := maxLineBytes - len(s.Prefix); remaining > 0 {
				s.Prefix = append(s.Prefix, body[:min(remaining, len(body))]...)
			}
			s.Total += int64(len(body))
			if len(body) > 0 {
				s.EndsCR = body[len(body)-1] == '\r'
			}
			if complete {
				original := s.Total
				ending := "lf"
				if s.EndsCR {
					ending = "crlf"
					original--
					if s.Total <= maxLineBytes {
						s.Prefix = s.Prefix[:max(0, len(s.Prefix)-1)]
					}
				}
				valid := utf8.Valid(s.Prefix)
				content := strings.ToValidUTF8(string(s.Prefix), "\ufffd")
				// PostgreSQL TEXT cannot store NUL. Preserve its location visibly and label the conversion.
				nul := strings.ContainsRune(content, 0)
				content = strings.ReplaceAll(content, "\x00", "\\u0000")
				fields := map[string]string{"record_kind": "raw_log", "timestamp_kind": "observed", "path": path, "line_ending": ending,
					"original_bytes": strconv.FormatInt(original, 10), "truncated": strconv.FormatBool(original > maxLineBytes),
					"utf8_replaced": strconv.FormatBool(!valid), "nul_escaped": strconv.FormatBool(nul),
					"source_event_id": digest(fmt.Sprintf("%s\x00%s\x00%s\x00%d", source, identity, s.Generation, s.Start))}
				// Escaped NULs can expand a line. Keep a UTF-8 boundary and declare that truncation too.
				if len(content) > 65536 {
					content = content[:65536]
					for !utf8.ValidString(content) {
						content = content[:len(content)-1]
					}
					fields["truncated"] = "true"
				}
				batch = append(batch, &pb.LogLine{Ts: s.Observed, Content: content, Fields: fields})
				batchBytes += len(content)
				s.Prefix = nil
				s.Total = 0
				s.EndsCR = false
				s.Observed = 0
				s.Start = s.Offset
			}
		}
		if readErr != nil && readErr != bufio.ErrBufferFull {
			if readErr != io.EOF {
				c.log.Warn("log file read failed", "source", source)
			}
			break
		}
	}
	if len(batch) > 0 && !c.send(source, batch) {
		return
	}
	c.files[path] = s
	c.saveState()
}
func (c *Collector) loadState() {
	var saved stateJSON
	err := securestate.ReadJSONLimit(c.statePath, &saved, 128<<10)
	if os.IsNotExist(err) {
		return
	}
	if err == nil && saved.Version == 2 && len(saved.Files) <= 4 {
		for path, s := range saved.Files {
			if len(path) > 4096 || s.Offset < 0 || s.Start < 0 || s.Start > s.Offset || s.Total != s.Offset-s.Start || len(s.Prefix) > maxLineBytes || int64(len(s.Prefix)) > s.Total || len(s.Generation) > 32 || len(s.Identity) > 128 {
				c.stateInvalid = true
				return
			}
			// Older bounded cursors without ends_cr still retain the complete
			// fragment when it fits in Prefix. A truncated fragment records its
			// actual last byte separately from its retained prefix.
			if s.Total == int64(len(s.Prefix)) {
				s.EndsCR = len(s.Prefix) > 0 && s.Prefix[len(s.Prefix)-1] == '\r'
				saved.Files[path] = s
			}
		}
		if saved.Files != nil {
			c.files = saved.Files
		}
		return
	}
	// Preserve old offsets once, then bind them to the actual opened file identity.
	var legacy map[string]int64
	if securestate.ReadJSONLimit(c.statePath, &legacy, 128<<10) == nil && legacy != nil && len(legacy) <= 4 {
		for path, off := range legacy {
			if off < 0 || len(path) > 4096 {
				c.stateInvalid = true
				return
			}
			c.files[path] = fileState{Offset: off, Start: off}
		}
		return
	}
	c.stateInvalid = true
}
func (c *Collector) saveState() bool {
	if err := securestate.WriteJSONLimit(c.statePath, stateJSON{Version: 2, Files: c.files}, 128<<10); err != nil {
		c.log.Warn("log cursor persistence failed")
		return false
	}
	return true
}
