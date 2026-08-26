package comm

import (
	"container/list"
	"sync"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// cmdDedup 指令幂等去重（协议设计 §3.2）：
// 容量 1000 的 LRU，记录 cmd_id → 最近一次 ACK。
// 重复指令：非终态仅重发上次 ACK；终态重发终态 ACK 且不重复执行。
// 基线核查等异步指令的终态 ACK 由执行 goroutine 写入，故需并发安全。
type cmdDedup struct {
	mu    sync.Mutex
	cap   int
	order *list.List               // elem.Value = cmd_id（string），front = 最旧
	items map[string]*list.Element // cmd_id → element
	acks  map[string]*pb.RptAck    // cmd_id → 最近 ACK
}

func newCmdDedup(capacity int) *cmdDedup {
	if capacity <= 0 {
		capacity = 1000
	}
	return &cmdDedup{cap: capacity, order: list.New(), items: map[string]*list.Element{}, acks: map[string]*pb.RptAck{}}
}

// Get 返回已记录的 ACK（nil 表示未见过该指令）
func (d *cmdDedup) Get(cmdID string) *pb.RptAck {
	d.mu.Lock()
	defer d.mu.Unlock()
	if el, ok := d.items[cmdID]; ok {
		d.order.MoveToBack(el) // 命中即续期
		return d.acks[cmdID]
	}
	return nil
}

// Put 记录指令的最近 ACK，超容量淘汰最旧条目
func (d *cmdDedup) Put(cmdID string, ack *pb.RptAck) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if el, ok := d.items[cmdID]; ok {
		d.acks[cmdID] = ack
		d.order.MoveToBack(el)
		return
	}
	if d.order.Len() >= d.cap {
		oldest := d.order.Front()
		if oldest != nil {
			delete(d.items, oldest.Value.(string))
			delete(d.acks, oldest.Value.(string))
			d.order.Remove(oldest)
		}
	}
	el := d.order.PushBack(cmdID)
	d.items[cmdID] = el
	d.acks[cmdID] = ack
}

// terminal ACK 是否已到终态（DONE/FAILED）
func terminal(a *pb.RptAck) bool {
	return a.GetStage() == pb.RptAck_DONE || a.GetStage() == pb.RptAck_FAILED
}
