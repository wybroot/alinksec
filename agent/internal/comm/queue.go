package comm

import (
	"bufio"
	"bytes"
	"fmt"
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
	mu   sync.Mutex
	path string
}

const (
	maxQueueBytes = 500 << 20      // 环形容量上限 500MB
	maxEntryAge   = 24 * time.Hour // 单条最长保留 24h
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
	defer f.Close()
	line, err := protojson.Marshal(r)
	if err != nil {
		return fmt.Errorf("序列化 Report: %w", err)
	}
	w := bufio.NewWriter(f)
	if _, err := w.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return q.compactLocked()
}

// compactLocked 环形淘汰：超容量/超龄时从最旧侧丢弃（Push 后调用，持锁）。
// 写入路径仅在跨过阈值时做一次全量重写，均摊开销可接受。
func (q *OfflineQueue) compactLocked() error {
	st, err := os.Stat(q.path)
	if err != nil || st.Size() <= maxQueueBytes {
		return nil
	}
	b, err := os.ReadFile(q.path)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-maxEntryAge).UnixMilli()
	// 第一遍：剔除超龄行，统计存活字节
	var lines [][]byte
	total := 0
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		r := &pb.Report{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(line, r); err == nil && r.Ts > 0 && r.Ts < cutoff {
			continue // 超龄：丢弃
		}
		lines = append(lines, line)
		total += len(line) + 1
	}
	// 第二遍：超容量时从最旧侧丢到 90% 配额（保留最新数据）
	budget := maxQueueBytes * 9 / 10
	drop := total - budget
	i := 0
	for drop > 0 && i < len(lines) {
		drop -= len(lines[i]) + 1
		i++
	}
	var kept []byte
	for ; i < len(lines); i++ {
		kept = append(kept, lines[i]...)
		kept = append(kept, '\n')
	}
	tmp := q.path + ".tmp"
	if err := os.WriteFile(tmp, kept, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, q.path)
}

// PopAll 取出全部待补传 Report（文件读入后清空；发送失败由调用方重新 Push）
func (q *OfflineQueue) PopAll() ([]*pb.Report, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	f, err := os.Open(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []*pb.Report
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4*1024*1024), 4*1024*1024) // 单条上限 4MB（协议设计 §4）
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		r := &pb.Report{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(line, r); err != nil {
			continue // 脏行跳过，不阻塞补传
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	if err := os.Truncate(q.path, 0); err != nil && !os.IsNotExist(err) {
		return out, err
	}
	return out, nil
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
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	_ = st
	return n
}
