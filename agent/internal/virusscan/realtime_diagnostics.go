package virusscan

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/alinksec/alinksec-agent/internal/clamav"
	"github.com/alinksec/alinksec-agent/internal/yara"
)

var (
	errSnapshotScope   = errors.New("opened parent escaped scan scope")
	errSnapshotType    = errors.New("invalid regular file")
	errSnapshotSize    = errors.New("file exceeds scan size limit")
	errSnapshotChanged = errors.New("file changed during read")
)

type realtimeIssueKey struct{ engine, phase, reason string }

type snapshotSinkError struct{ error }

func (e snapshotSinkError) Unwrap() error { return e.error }

type realtimeIssueWindow struct {
	at         time.Time
	suppressed uint64
}

func snapshotIssueCode(ctx context.Context, err error) string {
	var sinkErr snapshotSinkError
	switch {
	case ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	case errors.Is(err, os.ErrNotExist):
		return "file_missing"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case errors.Is(err, errSnapshotSize):
		return "file_limit"
	case errors.Is(err, errSnapshotType):
		return "not_regular"
	case errors.Is(err, errSnapshotChanged):
		return "file_changed"
	case errors.Is(err, errSnapshotScope):
		return "scope_changed"
	case errors.Is(err, errScanBudget):
		return "budget_exhausted"
	case errors.As(err, &sinkErr):
		return "stream_failed"
	default:
		return "read_failed"
	}
}

// Called under Engine.mu. Retain only fixed category keys, never file names or
// raw errors. Emit one representative per engine/phase/reason per minute, so
// temporary-file churn cannot produce one journal entry for every scan failure.
// These local diagnostics do not alter heartbeat counters or certify coverage.
func (e *Engine) realtimeFailure(engine, phase, path string, s snapshot, spent uint64, started time.Time, ctx context.Context, err, inputErr error) {
	reason := yara.Code(err)
	if engine == "clamav" {
		reason = clamav.Code(err)
	}
	if inputErr != nil {
		phase, reason = "input", snapshotIssueCode(ctx, inputErr)
	}
	key := realtimeIssueKey{engine, phase, reason}
	if e.realtimeIssues == nil {
		e.realtimeIssues = make(map[realtimeIssueKey]realtimeIssueWindow)
	}
	window := e.realtimeIssues[key]
	now := time.Now()
	if !window.at.IsZero() && now.Sub(window.at) < time.Minute {
		window.suppressed++
		e.realtimeIssues[key] = window
		return
	}
	e.realtimeIssues[key] = realtimeIssueWindow{at: now}
	size := int64(-1)
	if s.info != nil {
		size = s.info.Size()
	}
	e.log.Warn("实时引擎未覆盖文件", "engine", engine, "phase", phase, "reason", reason,
		"path", path, "size_bytes", size, "bytes_read", spent,
		"elapsed_ms", now.Sub(started).Milliseconds(), "suppressed", window.suppressed)
}
