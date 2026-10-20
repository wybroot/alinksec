package yara

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

const workerArg = "__alinksec_yara_worker_v1"

type workerResult struct {
	Version         string  `json:"version"`
	Matches         []Match `json:"matches"`
	Issue           string  `json:"issue"`
	AllocationLimit uint64  `json:"allocation_limit_bytes"`
}

func init() {
	if len(os.Args) == 2 && os.Args[1] == workerArg {
		debug.SetMemoryLimit(32 << 20)
		os.Exit(worker(os.Stdin, os.Stdout))
	}
}
func worker(in io.Reader, out io.Writer) int {
	result := workerResult{Version: nativeVersion()}
	if nativeVersion() == "" {
		result.Issue = "yara_not_built"
	} else if workerLimits() != nil {
		result.Issue = "yara_resource_limit"
	} else {
		var h [13]byte
		if _, err := io.ReadFull(in, h[:]); err != nil || string(h[:4]) != "AYR1" || h[4] > 1 {
			return 2
		}
		n, sec := binary.BigEndian.Uint32(h[5:9]), binary.BigEndian.Uint32(h[9:13])
		if n == 0 || n > MaxRuleBytes || sec < 1 || sec > 30 {
			return 2
		}
		var limitErr error
		result.AllocationLimit, limitErr = workerAllocationLimit()
		if limitErr != nil || result.AllocationLimit != 192<<20 {
			return 2
		}
		rules := make([]byte, n)
		if _, err := io.ReadFull(in, rules); err != nil {
			return 2
		}
		data, err := io.ReadAll(io.LimitReader(in, MaxFileBytes+1))
		if err != nil || int64(len(data)) > MaxFileBytes {
			return 2
		}
		if h[4] == 1 && len(data) != 0 {
			return 2
		}
		result.Matches, result.Issue = nativeScan(rules, data, h[4] == 1, int(sec))
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	return 0
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("YARA output limit")
	}
	return b.Buffer.Write(p)
}

type boundedWriter struct {
	io.Writer
	n int64
}

func (w *boundedWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > MaxFileBytes-w.n {
		return 0, issue("yara_file_limit")
	}
	n, err := w.Writer.Write(b)
	w.n += int64(n)
	return n, err
}

func runWorker(ctx context.Context, rules []byte, probe bool, consume func(context.Context, io.Writer) error) ([]Match, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, issue("yara_worker_failed")
	}
	cmd := exec.CommandContext(ctx, exe, workerArg)
	// No loader overrides, module data paths, or child process hooks are inherited.
	for _, key := range []string{"SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"} {
		if value := os.Getenv(key); value != "" {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Env = append(cmd.Env, "GOMEMLIMIT=32MiB", "GOMAXPROCS=1", "GOGC=50")
	cmd.WaitDelay = time.Second
	stdout, stderr := &cappedBuffer{limit: 32 << 10}, &cappedBuffer{limit: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, issue("yara_worker_failed")
	}
	if err = cmd.Start(); err != nil {
		pipe.Close()
		return nil, issue("yara_worker_failed")
	}
	cleanup, limitErr := limitProcess(cmd.Process)
	if limitErr != nil {
		pipe.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, issue("yara_resource_limit")
	}
	defer cleanup()
	var h [13]byte
	copy(h[:4], "AYR1")
	if probe {
		h[4] = 1
	}
	binary.BigEndian.PutUint32(h[5:9], uint32(len(rules)))
	seconds := uint32(10)
	if deadline, ok := ctx.Deadline(); ok {
		seconds = uint32(max(1, min(30, int(time.Until(deadline).Seconds())+1)))
	}
	binary.BigEndian.PutUint32(h[9:13], seconds)
	_, err = pipe.Write(h[:])
	if err == nil {
		_, err = pipe.Write(rules)
	}
	if err == nil && !probe {
		if consume == nil {
			err = issue("yara_worker_protocol")
		} else {
			err = consume(ctx, &boundedWriter{Writer: pipe})
		}
	}
	pipe.Close()
	if err != nil {
		cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if waitErr != nil || stderr.Len() != 0 {
		return nil, issue("yara_worker_failed")
	}
	var result workerResult
	d := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.Version != nativeVersion() {
		return nil, issue("yara_worker_protocol")
	}
	if result.Issue != "" {
		switch result.Issue {
		case "yara_compile_error", "yara_empty_rules", "yara_rule_limit", "yara_match_limit", "yara_timeout", "yara_scan_error", "yara_resource_limit", "yara_not_built":
			return nil, issue(result.Issue)
		}
		return nil, issue("yara_worker_protocol")
	}
	if result.AllocationLimit != 192<<20 {
		return nil, issue("yara_resource_limit")
	}
	if len(result.Matches) > 32 {
		return nil, issue("yara_match_limit")
	}
	seen := map[string]bool{}
	for _, m := range result.Matches {
		if !validRule(m.Rule) || m.Severity < 1 || m.Severity > 5 || seen[m.Rule] {
			return nil, issue("yara_worker_protocol")
		}
		seen[m.Rule] = true
	}
	sort.Slice(result.Matches, func(i, j int) bool {
		a, b := result.Matches[i], result.Matches[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Rule < b.Rule
	})
	return result.Matches, nil
}
func validRule(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_", c) && !(i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
