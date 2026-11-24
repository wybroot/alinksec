package comm

import (
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
	"google.golang.org/protobuf/proto"
)

const (
	defaultGeneralDedupCap       = 1000
	defaultProtectedDedupCap     = 4096
	defaultDestructiveRetention  = 24 * time.Hour
	maxDedupFileBytes            = 4 << 20
	maxDedupAckMessageBytes      = 32 << 10
	maxDedupCmdIDLen             = 128
	interruptedDestructiveReason = "interrupted during previous agent process; destructive replay refused pending review"
)

var (
	errCommandInvalidID       = errors.New("invalid command id")
	errCommandPayloadConflict = errors.New("command id payload conflict")
	errDedupCapacityExhausted = errors.New("destructive command deduplication capacity exhausted")
	errDedupJournalCorrupt    = errors.New("command deduplication journal invalid")
)

type commandClass struct {
	kind               string
	destructive        bool
	hasDedicatedLedger bool
}

// classifyCommand maps all 14 ACK-bearing proto Command payloads to their
// idempotency and destructive-replay safety boundaries.
func classifyCommand(cmd *pb.Command) commandClass {
	if cmd == nil {
		return commandClass{kind: "unknown"}
	}
	switch p := cmd.GetPayload().(type) {
	case *pb.Command_BaselineCheck:
		return commandClass{kind: "baseline_check"}
	case *pb.Command_VulnScan:
		return commandClass{kind: "vuln_scan"}
	case *pb.Command_PolicySync:
		return commandClass{kind: "policy_sync"}
	case *pb.Command_ProtectAction:
		switch p.ProtectAction.GetAction() {
		case pb.CmdProtectAction_ISOLATE_HOST:
			return commandClass{kind: "protect_isolate_host", destructive: true, hasDedicatedLedger: true}
		case pb.CmdProtectAction_RESTORE_ISOLATION:
			return commandClass{kind: "protect_restore_isolation", destructive: true, hasDedicatedLedger: true}
		case pb.CmdProtectAction_KILL_PROCESS:
			return commandClass{kind: "protect_kill_process", destructive: true}
		default:
			return commandClass{kind: "protect_action_unknown"}
		}
	case *pb.Command_AgentUpgrade:
		return commandClass{kind: "agent_upgrade", destructive: true, hasDedicatedLedger: true}
	case *pb.Command_CollectNow:
		return commandClass{kind: "collect_now"}
	case *pb.Command_AgentControl:
		switch p.AgentControl.GetAction() {
		case pb.CmdAgentControl_RESTART:
			return commandClass{kind: "agent_control_restart", destructive: true}
		case pb.CmdAgentControl_ARM_UNINSTALL:
			return commandClass{kind: "agent_control_arm_uninstall", destructive: true}
		case pb.CmdAgentControl_PAUSE_COLLECT:
			return commandClass{kind: "agent_control_pause_collect"}
		case pb.CmdAgentControl_RESUME_COLLECT:
			return commandClass{kind: "agent_control_resume_collect"}
		default:
			return commandClass{kind: "agent_control_unknown"}
		}
	case *pb.Command_VirusScan:
		return commandClass{kind: "virus_scan", destructive: true}
	case *pb.Command_VirusAction:
		return commandClass{kind: "virus_action", destructive: true}
	case *pb.Command_SignatureUpdate:
		return commandClass{kind: "signature_update", destructive: true}
	case *pb.Command_VulnFix:
		return commandClass{kind: "vuln_fix", destructive: true}
	case *pb.Command_WindowsUpdateScan:
		return commandClass{kind: "windows_update_scan"}
	case *pb.Command_ScapScan:
		return commandClass{kind: "scap_scan", hasDedicatedLedger: true}
	case *pb.Command_EvidenceCollect:
		return commandClass{kind: "evidence_collect", hasDedicatedLedger: true}
	default:
		return commandClass{kind: "unknown"}
	}
}

func commandDigest(cmd *pb.Command) (string, error) {
	if cmd == nil {
		return "", errors.New("nil command")
	}
	clone, ok := proto.Clone(cmd).(*pb.Command)
	if !ok {
		return "", errors.New("clone command failed")
	}
	clone.IssuedAt = 0
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

type dedupRecord struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind,omitempty"`
	Digest      string          `json:"digest,omitempty"`
	Destructive bool            `json:"destructive,omitempty"`
	BootID      string          `json:"boot_id,omitempty"`
	Stage       pb.RptAck_Stage `json:"stage"`
	Code        int32           `json:"code,omitempty"`
	Message     string          `json:"message,omitempty"`
	UpdatedAt   int64           `json:"updated_at"`
}

type dedupJournal struct {
	Schema    int           `json:"schema"`
	General   []dedupRecord `json:"general"`
	Protected []dedupRecord `json:"protected"`
}

type dedupEntry struct {
	record dedupRecord
	elem   *list.Element
}

// cmdDedup 指令幂等去重与跨进程持久台账（BKL-025）：
// 分为一般桶（general，容量 LRU 淘汰）与破坏性受保护桶（protected，24h 内不因普通流量淘汰）；
// 持久化至工作目录 cmd-dedup.json，并在破坏性指令执行前落盘运行意图。
type cmdDedup struct {
	mu                   sync.Mutex
	path                 string
	bootID               string
	generalCap           int
	protectedCap         int
	destructiveRetention time.Duration
	now                  func() time.Time
	generalOrder         *list.List // elem.Value = cmd_id（string），front = 最旧
	protectedOrder       *list.List // elem.Value = cmd_id（string），front = 最旧
	entries              map[string]*dedupEntry
}

func newBootID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("boot-%d", time.Now().UnixNano())
}

// newCmdDedup creates an in-memory command deduplicator for unit fixtures.
func newCmdDedup(capacity int) *cmdDedup {
	if capacity <= 0 {
		capacity = defaultGeneralDedupCap
	}
	protectedCap := defaultProtectedDedupCap
	if capacity > protectedCap {
		protectedCap = capacity
	}
	return &cmdDedup{
		bootID:               newBootID(),
		generalCap:           capacity,
		protectedCap:         protectedCap,
		destructiveRetention: defaultDestructiveRetention,
		now:                  time.Now,
		generalOrder:         list.New(),
		protectedOrder:       list.New(),
		entries:              map[string]*dedupEntry{},
	}
}

// newPersistentCmdDedup loads or initializes a fail-closed durable command ledger.
func newPersistentCmdDedup(workDir string, generalCap, protectedCap int) (*cmdDedup, error) {
	if generalCap <= 0 {
		generalCap = defaultGeneralDedupCap
	}
	if protectedCap <= 0 {
		protectedCap = defaultProtectedDedupCap
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return nil, err
	}
	d := &cmdDedup{
		path:                 filepath.Join(workDir, "cmd-dedup.json"),
		bootID:               newBootID(),
		generalCap:           generalCap,
		protectedCap:         protectedCap,
		destructiveRetention: defaultDestructiveRetention,
		now:                  time.Now,
		generalOrder:         list.New(),
		protectedOrder:       list.New(),
		entries:              map[string]*dedupEntry{},
	}
	if err := d.load(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *cmdDedup) load() error {
	var journal dedupJournal
	err := securestate.ReadJSONLimit(d.path, &journal, maxDedupFileBytes)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", errDedupJournalCorrupt, err)
	}
	if journal.Schema != 1 || len(journal.General) > d.generalCap || len(journal.Protected) > d.protectedCap {
		return errDedupJournalCorrupt
	}
	appendBucket := func(records []dedupRecord, expectedDestructive bool, order *list.List) error {
		for _, rec := range records {
			if !validDedupRecord(rec) || rec.Destructive != expectedDestructive {
				return errDedupJournalCorrupt
			}
			if _, dup := d.entries[rec.ID]; dup {
				return errDedupJournalCorrupt
			}
			rec.Message = clampUTF8(rec.Message, maxDedupAckMessageBytes)
			elem := order.PushBack(rec.ID)
			d.entries[rec.ID] = &dedupEntry{record: rec, elem: elem}
		}
		return nil
	}
	if err := appendBucket(journal.General, false, d.generalOrder); err != nil {
		return err
	}
	return appendBucket(journal.Protected, true, d.protectedOrder)
}

func validDedupRecord(r dedupRecord) bool {
	if r.ID == "" || len(r.ID) > maxDedupCmdIDLen || r.UpdatedAt <= 0 {
		return false
	}
	if r.Digest != "" && (len(r.Digest) != 64 || strings.Trim(r.Digest, "0123456789abcdef") != "") {
		return false
	}
	if len(r.Message) > maxDedupAckMessageBytes {
		return false
	}
	switch r.Stage {
	case pb.RptAck_RECEIVED, pb.RptAck_RUNNING, pb.RptAck_DONE, pb.RptAck_FAILED:
		return true
	default:
		return false
	}
}

// Get 返回已记录的 ACK 副本（nil 表示未见过该指令）
func (d *cmdDedup) Get(cmdID string) *pb.RptAck {
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry, ok := d.entries[cmdID]; ok {
		d.orderFor(entry.record.Destructive).MoveToBack(entry.elem)
		return recordToAck(entry.record)
	}
	return nil
}

// CheckOrBegin enforces cross-process idempotency, payload-binding and
// crash-safe destructive replay protection before command execution starts.
func (d *cmdDedup) CheckOrBegin(cmdID string, cls commandClass, digest string) (*pb.RptAck, error) {
	if cmdID == "" || len(cmdID) > maxDedupCmdIDLen {
		return nil, errCommandInvalidID
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	nowMs := d.now().UnixMilli()
	if entry, exists := d.entries[cmdID]; exists {
		if entry.record.Digest != "" && digest != "" && entry.record.Digest != digest {
			return nil, errCommandPayloadConflict
		}
		order := d.orderFor(entry.record.Destructive)
		if terminalRecord(entry.record) || entry.record.BootID == d.bootID {
			order.MoveToBack(entry.elem)
			return recordToAck(entry.record), nil
		}
		// Previous agent process terminated mid-flight.
		if entry.record.Destructive || cls.destructive {
			prev := entry.record
			entry.record.BootID = d.bootID
			entry.record.Stage = pb.RptAck_FAILED
			entry.record.Code = 1
			entry.record.Message = interruptedDestructiveReason
			entry.record.UpdatedAt = nowMs
			order.MoveToBack(entry.elem)
			if err := d.persistLocked(); err != nil {
				entry.record = prev
				return nil, err
			}
			return recordToAck(entry.record), nil
		}
		// Non-destructive commands interrupted mid-flight before terminal ACK may re-run cleanly.
		entry.record.BootID = d.bootID
		entry.record.Stage = pb.RptAck_RUNNING
		entry.record.Code = 0
		entry.record.Message = ""
		entry.record.UpdatedAt = nowMs
		order.MoveToBack(entry.elem)
		return nil, nil
	}

	if cls.destructive {
		if d.protectedOrder.Len() >= d.protectedCap {
			if !d.evictExpiredProtectedLocked(nowMs) {
				return nil, errDedupCapacityExhausted
			}
		}
	} else if d.generalOrder.Len() >= d.generalCap {
		d.evictGeneralLocked()
	}

	rec := dedupRecord{
		ID:          cmdID,
		Kind:        cls.kind,
		Digest:      digest,
		Destructive: cls.destructive,
		BootID:      d.bootID,
		Stage:       pb.RptAck_RUNNING,
		UpdatedAt:   nowMs,
	}
	order := d.orderFor(cls.destructive)
	elem := order.PushBack(cmdID)
	d.entries[cmdID] = &dedupEntry{record: rec, elem: elem}

	if cls.destructive && d.path != "" {
		if err := d.persistLocked(); err != nil {
			d.removeEntryLocked(cmdID, elem, cls.destructive)
			return nil, err
		}
	}
	return nil, nil
}

// Put 记录指令的最近 ACK（终态不可被非终态覆盖），超容量按桶淘汰。
func (d *cmdDedup) Put(cmdID string, ack *pb.RptAck) {
	_ = d.PutDurable(cmdID, ack)
}

// PutDurable records the ACK and atomically persists terminal outcomes to disk.
func (d *cmdDedup) PutDurable(cmdID string, ack *pb.RptAck) error {
	if cmdID == "" || len(cmdID) > maxDedupCmdIDLen || ack == nil {
		return nil
	}
	msg := clampUTF8(ack.GetMessage(), maxDedupAckMessageBytes)

	d.mu.Lock()
	defer d.mu.Unlock()
	nowMs := d.now().UnixMilli()

	if entry, ok := d.entries[cmdID]; ok {
		if terminalRecord(entry.record) {
			return nil
		}
		prev := entry.record
		entry.record.Stage = ack.GetStage()
		entry.record.Code = ack.GetCode()
		entry.record.Message = msg
		entry.record.BootID = d.bootID
		entry.record.UpdatedAt = nowMs
		d.orderFor(entry.record.Destructive).MoveToBack(entry.elem)
		if d.path != "" && terminal(ack) {
			if err := d.persistLocked(); err != nil {
				entry.record = prev
				return err
			}
		}
		return nil
	}

	if d.generalOrder.Len() >= d.generalCap {
		d.evictGeneralLocked()
	}
	rec := dedupRecord{
		ID:          cmdID,
		Destructive: false,
		BootID:      d.bootID,
		Stage:       ack.GetStage(),
		Code:        ack.GetCode(),
		Message:     msg,
		UpdatedAt:   nowMs,
	}
	elem := d.generalOrder.PushBack(cmdID)
	d.entries[cmdID] = &dedupEntry{record: rec, elem: elem}
	if d.path != "" && terminal(ack) {
		if err := d.persistLocked(); err != nil {
			d.removeEntryLocked(cmdID, elem, false)
			return err
		}
	}
	return nil
}

func (d *cmdDedup) orderFor(destructive bool) *list.List {
	if destructive {
		return d.protectedOrder
	}
	return d.generalOrder
}

func (d *cmdDedup) evictGeneralLocked() {
	var fallback *list.Element
	for el := d.generalOrder.Front(); el != nil; el = el.Next() {
		if fallback == nil {
			fallback = el
		}
		id := el.Value.(string)
		if entry, ok := d.entries[id]; ok && terminalRecord(entry.record) {
			d.removeEntryLocked(id, el, false)
			return
		}
	}
	if fallback != nil {
		d.removeEntryLocked(fallback.Value.(string), fallback, false)
	}
}

func (d *cmdDedup) evictExpiredProtectedLocked(nowMs int64) bool {
	cutoff := nowMs - d.destructiveRetention.Milliseconds()
	for el := d.protectedOrder.Front(); el != nil; el = el.Next() {
		id := el.Value.(string)
		entry, ok := d.entries[id]
		if ok && terminalRecord(entry.record) && entry.record.UpdatedAt <= cutoff {
			d.removeEntryLocked(id, el, true)
			return true
		}
	}
	return false
}

func (d *cmdDedup) removeEntryLocked(id string, el *list.Element, destructive bool) {
	delete(d.entries, id)
	if el != nil {
		d.orderFor(destructive).Remove(el)
	}
}

func (d *cmdDedup) persistLocked() error {
	if d.path == "" {
		return nil
	}
	journal := dedupJournal{
		Schema:    1,
		General:   make([]dedupRecord, 0, d.generalOrder.Len()),
		Protected: make([]dedupRecord, 0, d.protectedOrder.Len()),
	}
	for el := d.generalOrder.Front(); el != nil; el = el.Next() {
		if entry, ok := d.entries[el.Value.(string)]; ok {
			journal.General = append(journal.General, entry.record)
		}
	}
	for el := d.protectedOrder.Front(); el != nil; el = el.Next() {
		if entry, ok := d.entries[el.Value.(string)]; ok {
			journal.Protected = append(journal.Protected, entry.record)
		}
	}
	return securestate.WriteJSONLimit(d.path, journal, maxDedupFileBytes)
}

func clampUTF8(s string, maxBytes int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func recordToAck(r dedupRecord) *pb.RptAck {
	return &pb.RptAck{
		CmdId:   r.ID,
		Stage:   r.Stage,
		Code:    r.Code,
		Message: r.Message,
	}
}

func terminalRecord(r dedupRecord) bool {
	return r.Stage == pb.RptAck_DONE || r.Stage == pb.RptAck_FAILED
}

// terminal ACK 是否已到终态（DONE/FAILED）
func terminal(a *pb.RptAck) bool {
	return a.GetStage() == pb.RptAck_DONE || a.GetStage() == pb.RptAck_FAILED
}
