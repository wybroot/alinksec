// Package logcollect 登录/安全日志采集（docs/04 §2）：
// Linux tail /var/log/secure（Debian 系 /var/log/auth.log）；Windows 走 Security 事件日志。
// 产物 RptLogBatch 批量上报，服务端落 t_agent_log；轮询 offset 持久化防重启重采。
package logcollect

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const (
	maxLineBytes  = 4000 // 单行截断上限（服务端列宽对齐）
	maxBatchLines = 100  // 单批次行数上限
	stateFile     = "logtail.state.json"
)

// Collector 日志采集器：线程安全（offset 持久化互斥）
type Collector struct {
	log       *slog.Logger
	statePath string
	mu        sync.Mutex
	offsets   map[string]int64
	send      func(source string, lines []*pb.LogLine)
}

func New(workDir string, log *slog.Logger, send func(source string, lines []*pb.LogLine)) *Collector {
	c := &Collector{
		log:       log,
		statePath: filepath.Join(workDir, stateFile),
		offsets:   map[string]int64{},
		send:      send,
	}
	c.loadState()
	return c
}

// Run 阻塞采集主循环（平台分支见 _linux/_windows）
func (c *Collector) Run(ctx context.Context) {
	tk := time.NewTicker(pollInterval())
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			c.saveState()
			return
		case <-tk.C:
			c.pollOnce()
		}
	}
}

// tailFile 从上次 offset 增量读取一个文件；文件截断/轮转（offset>size）时重头采。
// offset 仅按完整行（含换行符）推进，半行留待下轮，防截断行丢失。
func (c *Collector) tailFile(path, source string) {
	c.mu.Lock()
	off := c.offsets[path]
	c.mu.Unlock()

	st, err := os.Stat(path)
	if err != nil {
		return // 文件不存在（未装 sshd / 权限不足）：静默跳过，下轮再试
	}
	if st.Size() < off {
		off = 0 // 轮转/截断：重头
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(off, 0); err != nil {
		return
	}

	br := bufio.NewReaderSize(f, 64*1024)
	var batch []*pb.LogLine
	pos := off
	now := time.Now().UnixMilli()
	for len(batch) < maxBatchLines {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			pos += int64(len(line))
			content := strings.TrimSpace(string(line))
			if content == "" {
				if rerr != nil {
					break
				}
				continue
			}
			if len(content) > maxLineBytes {
				content = content[:maxLineBytes]
			}
			batch = append(batch, &pb.LogLine{Ts: now, Content: content})
		}
		if rerr != nil {
			break // EOF 或读取异常：本轮结束（offset 未推进的部分下轮重读）
		}
	}
	if len(batch) > 0 {
		c.send(source, batch)
	}
	if pos > off {
		c.mu.Lock()
		c.offsets[path] = pos
		c.mu.Unlock()
		c.saveState()
	}
}

/* ---------- offset 持久化 ---------- */

type stateJSON map[string]int64

func (c *Collector) loadState() {
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		return
	}
	var s stateJSON
	if json.Unmarshal(data, &s) == nil {
		c.offsets = s
	}
}

func (c *Collector) saveState() {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.Marshal(c.offsets)
	if err != nil {
		return
	}
	tmp := c.statePath + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, c.statePath)
	}
}
