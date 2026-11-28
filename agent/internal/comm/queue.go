package comm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securestate"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

type reportPriority uint8

const (
	priorityEphemeral reportPriority = iota
	priorityBulk
	priorityStandard
	priorityCritical
)

func reportPriorityOf(r *pb.Report) reportPriority {
	if r == nil {
		return priorityStandard
	}
	switch r.GetPayload().(type) {
	case *pb.Report_Heartbeat, *pb.Report_IsolationState, *pb.Report_Metrics:
		return priorityEphemeral
	case *pb.Report_LogBatch:
		return priorityBulk
	case *pb.Report_Asset:
		return priorityStandard
	case *pb.Report_SecurityEvent,
		*pb.Report_Ack,
		*pb.Report_FixResult,
		*pb.Report_VirusResult,
		*pb.Report_Evidence,
		*pb.Report_ScapResult,
		*pb.Report_BaselineResult,
		*pb.Report_ScanResult,
		*pb.Report_WindowsUpdate:
		return priorityCritical
	default:
		// Legacy test fixtures or future durable payloads default to critical protection.
		return priorityCritical
	}
}

// QueueStats reports bounded numeric spool occupancy and eviction visibility.
type QueueStats struct {
	Bytes            int64  `json:"bytes"`
	LimitBytes       int64  `json:"limitBytes"`
	CriticalReserve  int64  `json:"criticalReserveBytes"`
	ExpiredDropped   uint64 `json:"expiredDropped"`
	BulkEvicted      uint64 `json:"bulkEvicted"`
	StandardEvicted  uint64 `json:"standardEvicted"`
	CriticalEvicted  uint64 `json:"criticalEvicted"`
	CapacityRejected uint64 `json:"capacityRejected"`
	CorruptSkipped   uint64 `json:"corruptSkipped"`
}

// OfflineQueue 断线期间的上报离线队列（JSONL 文件持久化，逐行追加）。
// 分级淘汰语义（BKL-028）：超龄/损坏先清理，再按 Bulk(原始日志) → Standard(资产) → Critical(安全事件/回执/结果)
// 优先淘汰；非关键上报不挤占 Critical 预留空间，且受工作目录总预算看护。
type OfflineQueue struct {
	mu              sync.Mutex
	path            string
	lastCompaction  time.Time
	offset          int64
	peekEnd         int64
	peeked          *pb.Report
	sentAt          time.Time
	directorySynced bool

	maxBytes        int64
	criticalReserve int64
	budget          *workdirBudget
	stats           QueueStats
	now             func() time.Time
}

const (
	compactEvery                = 5 * time.Minute
	maxQueueBytes               = 256 << 20 // 队列上限 256 MiB（为其余工作目录文件留足 <500 MiB 余量）
	defaultCriticalReserveBytes = 64 << 20  // 64 MiB 专供高危安全事件/ACK/处置结果保留
	maxRecordBytes              = 4 << 20
	maxEntryAge                 = 24 * time.Hour // 单条最长保留 24h
)

// NewOfflineQueue 在工作目录下创建队列文件并绑定工作目录总预算看护
func NewOfflineQueue(workDir string) (*OfflineQueue, error) {
	dir := filepath.Join(workDir, "queue")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	if err := securestate.SyncDirectory(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	return &OfflineQueue{
		path:   filepath.Join(dir, "pending.jsonl"),
		budget: newWorkdirBudget(workDir),
	}, nil
}

func (q *OfflineQueue) SetBudget(b *workdirBudget) {
	q.mu.Lock()
	q.budget = b
	q.mu.Unlock()
}

func (q *OfflineQueue) limitBytes() int64 {
	if q.maxBytes > 0 {
		return q.maxBytes
	}
	return maxQueueBytes
}

func (q *OfflineQueue) reserveBytes() int64 {
	limit := q.limitBytes()
	if q.criticalReserve > 0 && q.criticalReserve < limit {
		return q.criticalReserve
	}
	r := limit / 4
	if r > defaultCriticalReserveBytes {
		r = defaultCriticalReserveBytes
	}
	return r
}

func (q *OfflineQueue) capForPriority(prio reportPriority) int64 {
	limit := q.limitBytes()
	if prio >= priorityCritical {
		return limit
	}
	return max(int64(0), limit-q.reserveBytes())
}

func (q *OfflineQueue) nowTime() time.Time {
	if q.now != nil {
		return q.now()
	}
	return time.Now()
}

func (q *OfflineQueue) Stats() QueueStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	stats := q.stats
	stats.LimitBytes = q.limitBytes()
	stats.CriticalReserve = q.reserveBytes()
	if st, err := os.Stat(q.path); err == nil {
		stats.Bytes = st.Size()
	} else if os.IsNotExist(err) {
		stats.Bytes = 0
	}
	return stats
}

// Push 追加一条待补传 Report
func (q *OfflineQueue) Push(r *pb.Report) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	line, err := protojson.Marshal(r)
	if err != nil {
		return fmt.Errorf("序列化 Report: %w", err)
	}
	if len(line)+1 > maxRecordBytes {
		return fmt.Errorf("report exceeds 4MiB queue limit")
	}

	prio := reportPriorityOf(r)
	capLimit := q.capForPriority(prio)

	st, err := os.Stat(q.path)
	var curSize int64
	separator := false
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		curSize = st.Size()
		if curSize > 0 {
			rf, rerr := os.Open(q.path)
			if rerr != nil {
				return rerr
			}
			var last [1]byte
			_, readErr := rf.ReadAt(last[:], curSize-1)
			_ = rf.Close()
			if readErr != nil {
				return readErr
			}
			separator = last[0] != '\n'
		}
	}

	appendBytes := int64(len(line) + 1)
	if separator {
		appendBytes++
	}

	// Blocked send keeps the peeked cursor stable; non-critical reports never consume critical headroom.
	if q.peeked != nil {
		if curSize+appendBytes > capLimit {
			q.stats.CapacityRejected++
			if prio < priorityCritical {
				return fmt.Errorf("non-critical spool capacity reserved for critical events")
			}
			return fmt.Errorf("raw log spool capacity unavailable")
		}
	} else if curSize+appendBytes > capLimit {
		targetAfter := max(int64(0), min(capLimit-appendBytes, capLimit*9/10-appendBytes))
		if err := q.compactForAdmissionLocked(prio, appendBytes, capLimit, targetAfter); err != nil {
			q.stats.CapacityRejected++
			return err
		}
		if st2, err2 := os.Stat(q.path); err2 == nil {
			curSize = st2.Size()
			separator = false
		} else if os.IsNotExist(err2) {
			curSize = 0
			separator = false
		}
	}

	if q.budget != nil {
		if err := q.budget.CanAdmit(prio, appendBytes); err != nil {
			if q.peeked == nil && curSize > 0 {
				// Attempt priority eviction inside queue to free workdir headroom before rejecting.
				targetAfter := max(int64(0), curSize-appendBytes*2)
				if curSize < appendBytes*2 {
					targetAfter = 0
				}
				if cerr := q.compactForAdmissionLocked(prio, appendBytes, capLimit, targetAfter); cerr == nil {
					if err2 := q.budget.CanAdmit(prio, appendBytes); err2 == nil {
						err = nil
					} else {
						err = err2
					}
				}
			}
			if err != nil {
				q.stats.CapacityRejected++
				return err
			}
		}
	}

	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	if separator {
		if err := w.WriteByte('\n'); err != nil {
			_ = f.Close()
			return err
		}
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if stAfter, serr := os.Stat(q.path); serr == nil {
		q.stats.Bytes = stAfter.Size()
	}
	if !q.directorySynced {
		if err := securestate.SyncDirectory(filepath.Dir(q.path)); err != nil {
			return err
		}
		q.directorySynced = true
	}
	return q.compactLocked()
}

func (q *OfflineQueue) compactLocked() error {
	return q.compactCoreLocked(priorityCritical, q.limitBytes(), false, 0, 0)
}

func (q *OfflineQueue) compactForAdmissionLocked(incomingPrio reportPriority, appendBytes, capLimit, targetAfter int64) error {
	return q.compactCoreLocked(incomingPrio, capLimit, true, appendBytes, targetAfter)
}

// compactCoreLocked runs a 2-pass streaming O(1)-memory compaction:
// pass 1 computes per-priority totals & validates scanner limits without touching disk;
// pass 2 removes expired/corrupt records and lowest-priority entries first in chronological order.
func (q *OfflineQueue) compactCoreLocked(incomingPrio reportPriority, capLimit int64, forAdmission bool, appendBytes, targetAfter int64) error {
	st, err := os.Stat(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			q.stats.Bytes = 0
			return nil
		}
		return err
	}
	now := q.nowTime()
	if !forAdmission {
		needsAgeSweep := q.lastCompaction.IsZero() || now.Sub(q.lastCompaction) >= compactEvery
		if st.Size() <= q.limitBytes() && !needsAgeSweep && q.offset < q.limitBytes()/4 {
			q.stats.Bytes = st.Size()
			return nil
		}
	}
	// A peeked record's byte position remains stable until Ack/Release.
	if q.peeked != nil {
		return nil
	}

	cutoff := now.Add(-maxEntryAge).UnixMilli()
	var total, bulkBytes, standardBytes, criticalBytes, protectedBytes int64
	var corruptCount, expiredCount uint64

	err = q.visitFromOffsetLocked(func(line []byte, prio reportPriority, recTs int64, parseErr error) error {
		recLen := int64(len(line) + 1)
		if parseErr != nil {
			corruptCount++
			return nil
		}
		if recTs > 0 && recTs < cutoff {
			expiredCount++
			return nil
		}
		total += recLen
		if prio > incomingPrio {
			protectedBytes += recLen
		}
		switch prio {
		case priorityBulk:
			bulkBytes += recLen
		case priorityStandard:
			standardBytes += recLen
		default:
			criticalBytes += recLen
		}
		return nil
	})
	if err != nil {
		return err
	}

	if forAdmission {
		if protectedBytes+appendBytes > capLimit {
			return fmt.Errorf("higher priority backlog consumes queue capacity")
		}
	}

	if !forAdmission && q.offset == 0 && corruptCount == 0 && expiredCount == 0 && total == st.Size() && total <= q.limitBytes() {
		q.lastCompaction = now
		q.stats.Bytes = total
		return nil
	}

	desired := targetAfter
	if !forAdmission {
		if total <= q.limitBytes() {
			desired = total
		} else {
			desired = q.limitBytes() * 9 / 10
		}
	}
	needDrop := max(int64(0), total-desired)
	var dropBulk, dropStandard, dropCritical int64
	if needDrop > 0 {
		dropBulk = min(needDrop, bulkBytes)
		needDrop -= dropBulk
		if incomingPrio >= priorityStandard {
			dropStandard = min(needDrop, standardBytes)
			needDrop -= dropStandard
		}
		if incomingPrio >= priorityCritical {
			dropCritical = min(needDrop, criticalBytes)
		}
	}

	tmp := q.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	w := bufio.NewWriterSize(out, 64<<10)

	var writtenBytes int64
	var evictedBulk, evictedStandard, evictedCritical uint64
	err = q.visitFromOffsetLocked(func(line []byte, prio reportPriority, recTs int64, parseErr error) error {
		if parseErr != nil || (recTs > 0 && recTs < cutoff) {
			return nil
		}
		recLen := int64(len(line) + 1)
		switch prio {
		case priorityBulk:
			if dropBulk > 0 {
				dropBulk -= recLen
				evictedBulk++
				return nil
			}
		case priorityStandard:
			if dropStandard > 0 {
				dropStandard -= recLen
				evictedStandard++
				return nil
			}
		default:
			if dropCritical > 0 {
				dropCritical -= recLen
				evictedCritical++
				return nil
			}
		}
		if _, werr := w.Write(line); werr != nil {
			return werr
		}
		if werr := w.WriteByte('\n'); werr != nil {
			return werr
		}
		writtenBytes += recLen
		return nil
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
	q.stats.Bytes = writtenBytes
	q.stats.ExpiredDropped += expiredCount
	q.stats.CorruptSkipped += corruptCount
	q.stats.BulkEvicted += evictedBulk
	q.stats.StandardEvicted += evictedStandard
	q.stats.CriticalEvicted += evictedCritical
	q.budget.invalidate()
	// Rename has already changed the byte positions even if directory sync
	// fails. Keep the live cursor consistent and retry durability on next Push.
	q.directorySynced = false
	if err := securestate.SyncDirectory(filepath.Dir(q.path)); err != nil {
		return err
	}
	q.directorySynced = true
	return nil
}

func (q *OfflineQueue) visitFromOffsetLocked(fn func(line []byte, prio reportPriority, ts int64, parseErr error) error) error {
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
		parseErr := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(line, r)
		prio := priorityCritical
		var ts int64
		if parseErr == nil {
			prio = reportPriorityOf(r)
			ts = r.Ts
		}
		if err := fn(line, prio, ts, parseErr); err != nil {
			return err
		}
	}
	return sc.Err()
}

func queueScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxRecordBytes)
	return sc
}

// Peek loads one bounded record. Durable receipts advance the queue. A
// restart may replay acknowledged records before the last compaction; stable
// report IDs provide at-least-once delivery without holding the backlog in RAM.
func (q *OfflineQueue) Peek() (*pb.Report, error) {
	if !q.mu.TryLock() {
		return nil, nil
	}
	defer q.mu.Unlock()
	now := q.nowTime()
	cutoff := now.Add(-maxEntryAge).UnixMilli()
	if q.peeked != nil && q.peeked.Ts > 0 && q.peeked.Ts < cutoff {
		q.offset = q.peekEnd
		q.peeked = nil
		q.sentAt = time.Time{}
		q.stats.ExpiredDropped++
	}
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
		parseErr := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(line, r)
		if parseErr != nil {
			q.offset = end
			q.stats.CorruptSkipped++
			continue
		}
		if r.Ts > 0 && r.Ts < cutoff {
			q.offset = end
			q.stats.ExpiredDropped++
			continue
		}
		q.peeked, q.peekEnd = r, end
		q.sentAt = time.Time{}
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
		q.stats.Bytes = 0
		q.budget.invalidate()
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
	q.sentAt = time.Time{}
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

// Receipt advances only the exact in-flight report. Lost receipts safely replay.
func (q *OfflineQueue) Receipt(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.peeked == nil || q.peeked.ReportId != id {
		return false
	}
	q.offset = q.peekEnd
	q.peeked = nil
	q.sentAt = time.Time{}
	if err := q.compactLocked(); err != nil {
		return false
	}
	return true
}
func (q *OfflineQueue) ShouldSend(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.peeked == nil || q.peeked.ReportId != id || !q.sentAt.IsZero() && q.nowTime().Sub(q.sentAt) < 5*time.Second {
		return false
	}
	q.sentAt = q.nowTime()
	return true
}
