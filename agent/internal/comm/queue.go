package comm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// OfflineQueue 断线期间的上报离线队列（JSONL 文件持久化，逐行追加）。
// 环形语义（docs/01 §6.2）：总大小超 500MB 或单条超 24h 时丢最旧数据。
type OfflineQueue struct {
	mu             sync.Mutex
	path           string
	lastCompaction time.Time
	offset         int64
	peekEnd        int64
	peeked         *pb.Report
}

const (
	compactEvery   = 5 * time.Minute
	maxQueueBytes  = 500 << 20 // 环形容量上限 500MB
	maxRecordBytes = 4 << 20
	maxEntryAge    = 24 * time.Hour // 单条最长保留 24h
)

// NewOfflineQueue 在工作目录下创建队列文件
func NewOfflineQueue(workDir string) (*OfflineQueue, error) {
	dir := filepath.Join(workDir, "queue")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	return &OfflineQueue{path: filepath.Join(dir, "pending.jsonl")}, nil
}

// Push 追加一条待补传 Report
func (q *OfflineQueue) Push(r *pb.Report) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	line, err := protojson.Marshal(r)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("序列化 Report: %w", err)
	}
	if len(line)+1 > maxRecordBytes {
		_ = f.Close()
		return fmt.Errorf("report exceeds 4MiB queue limit")
	}
	w := bufio.NewWriter(f)
	if _, err := w.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return q.compactLocked()
}

// compactLocked 环形淘汰：超容量/超龄时从最旧侧丢弃（Push 后调用，持锁）。
// 写入路径仅在跨过阈值时做一次全量重写，均摊开销可接受。
func (q *OfflineQueue) compactLocked() error {
	st, err := os.Stat(q.path)
	if err != nil {
		return nil
	}
	now := time.Now()
	needsAgeSweep := q.lastCompaction.IsZero() || now.Sub(q.lastCompaction) >= compactEvery
	if st.Size() <= maxQueueBytes && !needsAgeSweep {
		return nil
	}
	// A peeked record's byte position remains stable until Ack/Release.
	if q.peeked != nil {
		return nil
	}
	cutoff := now.Add(-maxEntryAge).UnixMilli()
	visit := func(fn func([]byte) error) error {
		f, err := os.Open(q.path)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err = f.Seek(q.offset, io.SeekStart); err != nil {
			return err
		}
		sc := queueScanner(f)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			r := new(pb.Report)
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(line, r); err != nil {
				continue
			}
			if r.Ts > 0 && r.Ts < cutoff {
				continue
			}
			if err := fn(line); err != nil {
				return err
			}
		}
		return sc.Err()
	}
	var total int64
	if err := visit(func(line []byte) error { total += int64(len(line) + 1); return nil }); err != nil {
		return err
	}
	if q.offset == 0 && total == st.Size() && total <= maxQueueBytes {
		q.lastCompaction = now
		return nil
	}
	drop := max(int64(0), total-maxQueueBytes*9/10)
	tmp := q.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	w := bufio.NewWriterSize(out, 64<<10)
	err = visit(func(line []byte) error {
		if drop > 0 {
			drop -= int64(len(line) + 1)
			return nil
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		return w.WriteByte('\n')
	})
	if err == nil {
		err = w.Flush()
	}
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, q.path); err != nil {
		return err
	}
	q.offset = 0
	q.lastCompaction = now
	return nil
}

func queueScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxRecordBytes)
	return sc
}

// Peek loads one bounded record. Ack advances only after successful Send. A
// restart may replay acknowledged records before the last compaction; stable
// report IDs provide at-least-once delivery without holding the backlog in RAM.
func (q *OfflineQueue) Peek() (*pb.Report, error) {
	if !q.mu.TryLock() {
		return nil, nil
	}
	defer q.mu.Unlock()
	if q.peeked != nil {
		return q.peeked, nil
	}
	f, err := os.Open(q.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err = f.Seek(q.offset, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	sc := queueScanner(f)
	end := q.offset
	for skipped := 0; skipped < 64 && sc.Scan(); skipped++ {
		line := sc.Bytes()
		end += int64(len(line) + 1)
		r := new(pb.Report)
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(line, r); err != nil || r.Ts > 0 && r.Ts < time.Now().Add(-maxEntryAge).UnixMilli() {
			q.offset = end
			continue
		}
		q.peeked, q.peekEnd = r, end
		f.Close()
		return r, nil
	}
	err = sc.Err()
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	st, err := os.Stat(q.path)
	if err != nil {
		return nil, err
	}
	if q.offset >= st.Size() {
		if err := os.Truncate(q.path, 0); err != nil {
			return nil, err
		}
		q.offset = 0
	}
	return nil, nil
}

func (q *OfflineQueue) Ack() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.peeked != nil {
		q.offset = q.peekEnd
		q.peeked = nil
	}
}

// TryAck yields to append/compaction rather than blocking control traffic.
// A contended acknowledgement is retried by resending the same stable report.
func (q *OfflineQueue) TryAck() bool {
	if !q.mu.TryLock() {
		return false
	}
	defer q.mu.Unlock()
	if q.peeked != nil {
		q.offset = q.peekEnd
		q.peeked = nil
	}
	return true
}
func (q *OfflineQueue) Release() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.peeked = nil
}

// Len 待补传条数（诊断用）
func (q *OfflineQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	st, err := os.Stat(q.path)
	if err != nil {
		return 0
	}
	// 粗略计数：按行扫描（队列长度有限，开销可接受）
	f, err := os.Open(q.path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := queueScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	_ = st
	return n
}
