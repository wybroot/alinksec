// Package windowsupdate installs only an explicitly approved WUA identity.
// Registry application inventory and KB display names are never install targets.
package windowsupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
)

const maxRecords = 1024

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var numeric = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

type Update struct {
	ID       string   `json:"update_id"`
	Revision int      `json:"revision"`
	Title    string   `json:"title"`
	KB       []string `json:"kb"`
	Size     int64    `json:"size"`
	Eula     string   `json:"eula_digest"`
	Eligible bool     `json:"eligible"`
	Reason   string   `json:"reason"`
}
type Snapshot struct {
	Contract       int      `json:"contract"`
	Status         string   `json:"status"`
	Error          string   `json:"error"`
	BootID         string   `json:"boot_id"`
	HostIdentity   string   `json:"host_identity"`
	RebootRequired bool     `json:"reboot_required"`
	Updates        []Update `json:"updates"`
}
type Payload struct {
	Contract     int    `json:"contract"`
	HostIdentity string `json:"host_identity"`
	Update       Update `json:"update"`
	Deadline     int64  `json:"dispatch_deadline_unix_ms"`
}
type Request struct {
	Operation    string `json:"operation"`
	HostIdentity string `json:"host_identity"`
	Update       Update `json:"update"`
	Deadline     int64  `json:"deadline"`
}
type Outcome struct {
	Contract       int    `json:"contract"`
	BootID         string `json:"boot_id"`
	UpdateID       string `json:"update_id"`
	Revision       int    `json:"revision"`
	HostIdentity   string `json:"host_identity"`
	Phase          string `json:"phase"`
	RebootRequired bool   `json:"reboot_required"`
	Installed      bool   `json:"installed"`
	ResultCode     int    `json:"result_code"`
	HResult        int64  `json:"hresult"`
	Error          string `json:"error"`
}
type response struct {
	Snapshot
	Outcome
	Update *Update `json:"update,omitempty"`
}
type runner func(context.Context, Request) (response, error)
type record struct {
	Task          string            `json:"task"`
	Ref           string            `json:"ref"`
	Pin           string            `json:"pin"`
	Payload       Payload           `json:"payload"`
	Phase         string            `json:"phase"`
	Result        *pb.FixResultItem `json:"result"`
	InstallBootID string            `json:"install_boot_id"`
	InstallReboot bool              `json:"install_reboot"`
	Receipt       string            `json:"receipt"`
}

func Scan(deadline int64) Snapshot { return scanWith(deadline, nativeRun) }
func scanWith(deadline int64, run runner) Snapshot {
	failed := Snapshot{Contract: int(ExecutionContract()), Status: "failed", Error: "wua_scan_failed", Updates: []Update{}}
	if ExecutionContract() == 0 {
		failed.Status = "unsupported"
		failed.Error = "unsupported_platform"
		return failed
	}
	if deadline <= time.Now().UnixMilli() || deadline > time.Now().Add(11*time.Minute).UnixMilli() {
		failed.Error = "scan_expired"
		return failed
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(deadline))
	defer cancel()
	r, err := run(ctx, Request{Operation: "scan", Deadline: deadline})
	if err != nil {
		return failed
	}
	s := r.Snapshot
	if s.Contract != 1 || s.Status != "complete" || !digest.MatchString(s.HostIdentity) || len(s.Updates) > 256 {
		return failed
	}
	seen := map[string]bool{}
	for _, u := range s.Updates {
		key := fmt.Sprintf("%s:%d", u.ID, u.Revision)
		if !validUpdate(u) || seen[key] {
			return failed
		}
		seen[key] = true
	}
	return s
}
func validUpdate(u Update) bool {
	if !guid.MatchString(u.ID) || u.Revision < 1 || u.Revision > 2147483647 || len(u.Title) < 1 || len(u.Title) > 512 || len(u.KB) > 32 || u.Size < 0 || u.Size > 4<<30 || !digest.MatchString(u.Eula) || len(u.Reason) > 128 {
		return false
	}
	for _, kb := range u.KB {
		if len(kb) < 4 || len(kb) > 12 || strings.Trim(kb, "0123456789") != "" {
			return false
		}
	}
	return !u.Eligible || (len(u.KB) > 0 && u.Reason == "")
}
func pin(p Payload) string {
	p.Deadline = 0
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func evidence(r Outcome) string { b, _ := json.Marshal(r); return string(b) }
func outcome(p Payload, phase, issue string) Outcome {
	return Outcome{Contract: 1, UpdateID: p.Update.ID, Revision: p.Update.Revision, HostIdentity: p.HostIdentity, Phase: phase, Error: issue}
}

func Repair(task, ref, payload, workDir string) *pb.FixResultItem {
	if ExecutionContract() == 0 {
		return &pb.FixResultItem{RefId: ref, Log: "当前系统不支持 Windows Update Agent"}
	}
	return repairWith(task, ref, payload, workDir, nativeRun)
}
func repairWith(task, ref, payload, workDir string, run runner) *pb.FixResultItem {
	result := &pb.FixResultItem{RefId: ref}
	var p Payload
	if len(payload) > 16384 || json.Unmarshal([]byte(payload), &p) != nil || p.Contract != 1 || !digest.MatchString(p.HostIdentity) || !validUpdate(p.Update) || !p.Update.Eligible || !numeric.MatchString(task) || !numeric.MatchString(ref) {
		result.Log = "Windows 更新执行契约或固定目标无效，未执行安装"
		return result
	}
	result.ExecutionEvidence = evidence(outcome(p, "failed", "preflight_failed"))
	dir := filepath.Join(workDir, "windows-updates")
	if err := securestate.PrivateDir(dir); err != nil {
		result.Log = "无法保护更新恢复目录，未安装"
		return result
	}
	unlock, err := securestate.Lock(dir)
	if err != nil {
		result.Log = "已有 Windows 更新任务执行中，未安装"
		return result
	}
	defer unlock()
	path := filepath.Join(dir, task+"-"+ref+".json")
	var rec record
	if err = securestate.ReadJSON(path, &rec); err == nil {
		if rec.Pin != pin(p) || rec.Task != task || rec.Ref != ref {
			result.Log = "持久化更新目标不一致，拒绝重放"
			return result
		}
		if rec.Result != nil {
			return rec.Result
		}
		// A crash may occur after WUA accepted Install but before the result was saved.
		// Verification is safe; submitting Install again is not.
		return verifyRecord(path, &rec, run)
	} else if !os.IsNotExist(err) {
		result.Log = "更新恢复记录损坏，拒绝安装"
		return result
	}
	if p.Deadline <= time.Now().UnixMilli() || p.Deadline > time.Now().Add(31*time.Minute).UnixMilli() {
		result.Log = "任务或维护窗口已结束，未开始安装"
		return result
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) >= maxRecords+1 {
		result.Log = "更新恢复记录容量已满，请人工归档后重试"
		return result
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(p.Deadline))
	defer cancel()
	// Download is also exact-identity and source-bound; it never accepts a new EULA.
	r, err := run(ctx, Request{Operation: "download", HostIdentity: p.HostIdentity, Update: p.Update, Deadline: p.Deadline})
	if err != nil || r.Outcome.Phase != "downloaded" || !matches(p, r.Outcome) {
		result.Log = "更新已变化、下载失败、待重启或不可静默安装，未开始安装"
		return result
	}
	if time.Now().UnixMilli() >= p.Deadline {
		result.Log = "下载后维护窗口已结束，未开始安装"
		return result
	}
	rec = record{Task: task, Ref: ref, Pin: pin(p), Payload: p, Phase: "intent", InstallBootID: r.Outcome.BootID, InstallReboot: true}
	if securestate.WriteJSON(path, &rec) != nil {
		result.Log = "安装意图无法持久化，未开始安装"
		return result
	}
	// Once the intent is durable, an interrupted/unknown call is never retried as an install.
	r, err = run(ctx, Request{Operation: "install", HostIdentity: p.HostIdentity, Update: p.Update, Deadline: p.Deadline})
	if err != nil || !matches(p, r.Outcome) || r.Outcome.Phase != "installed" || r.Outcome.ResultCode != 2 || r.Outcome.HResult != 0 {
		rec.Phase = "uncertain"
		result.Log = "原生安装未确认成功，可能仍在后台执行；不自动重装或回滚，请人工检查"
		result.ExecutionEvidence = evidence(outcome(p, "uncertain", "install_unconfirmed"))
		rec.Result = result
		// Keep uncertain records available for read-only reconciliation.
		_ = securestate.WriteJSON(path, &rec)
		return result
	}
	rec.Phase = "verify"
	rec.InstallReboot = r.Outcome.RebootRequired
	if securestate.WriteJSON(path, &rec) != nil {
		result.Log = "安装结果无法持久化，保留不确定意图；不自动重装"
		result.ExecutionEvidence = evidence(outcome(p, "uncertain", "journal_write_failed"))
		return result
	}
	return verifyRecord(path, &rec, run)
}
func matches(p Payload, r Outcome) bool {
	return r.Contract == 1 && r.HostIdentity == p.HostIdentity && r.UpdateID == p.Update.ID && r.Revision == p.Update.Revision
}
func verifyRecord(path string, rec *record, run runner) *pb.FixResultItem {
	r := &pb.FixResultItem{RefId: rec.Ref}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	reply, err := run(ctx, Request{Operation: "verify", HostIdentity: rec.Payload.HostIdentity, Update: rec.Payload.Update, Deadline: time.Now().Add(90 * time.Second).UnixMilli()})
	o := reply.Outcome
	if err != nil || !matches(rec.Payload, o) || !o.Installed {
		r.Log = "尚未确认指定修订已安装，保留恢复记录；不自动重装"
		o = outcome(rec.Payload, "uncertain", "verification_unconfirmed")
		rec.Phase = "uncertain"
	} else if o.RebootRequired || (rec.InstallReboot && (o.BootID == "" || o.BootID == rec.InstallBootID)) {
		r.Success = true
		r.RebootRequired = true
		r.Log = "原生安装已确认，等待人工重启后复核；未自动重启"
		o.Phase = "pending_reboot"
		o.RebootRequired = true
		rec.Phase = "pending_reboot"
	} else {
		r.Success = true
		r.Verified = true
		r.Log = "Windows Update Agent 已确认指定更新及修订已安装，无待重启状态"
		o.Phase = "verified"
		rec.Phase = "complete"
	}
	r.ExecutionEvidence = evidence(o)
	rec.Result = r
	if securestate.WriteJSON(path, rec) != nil {
		r.Success = false
		r.Verified = false
		r.Log = "安装后恢复记录无法保存，请人工检查；不自动重装"
		r.ExecutionEvidence = evidence(outcome(rec.Payload, "uncertain", "journal_write_failed"))
	}
	return r
}

// Reconcile performs only read-only installed-state checks. Completed records are
// retained for durable replay and never submitted for installation a second time.
func Reconcile(workDir string) []*pb.RptFixResult { return reconcileWith(workDir, nativeRun) }
func reconcileWith(workDir string, run runner) []*pb.RptFixResult {
	dir := filepath.Join(workDir, "windows-updates")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > maxRecords+1 {
		return nil
	}
	unlock, err := securestate.Lock(dir)
	if err != nil {
		return nil
	}
	defer unlock()
	var results []*pb.RptFixResult
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		var rec record
		if securestate.ReadJSON(path, &rec) != nil || !numeric.MatchString(rec.Task) || !numeric.MatchString(rec.Ref) || e.Name() != rec.Task+"-"+rec.Ref+".json" || rec.Pin != pin(rec.Payload) {
			continue
		}
		if rec.Phase == "complete" {
			if rec.Result != nil && rec.Receipt != hashEvidence(rec.Result.ExecutionEvidence) {
				results = append(results, &pb.RptFixResult{TaskId: rec.Task, Results: []*pb.FixResultItem{rec.Result}})
			}
			continue
		}
		if rec.Phase == "closed" {
			continue
		}
		if checked >= 4 {
			break
		}
		checked++
		result := verifyRecord(path, &rec, run)
		results = append(results, &pb.RptFixResult{TaskId: rec.Task, Results: []*pb.FixResultItem{result}})
	}
	return results
}

func hashEvidence(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func Receipt(workDir string, receipts []string) {
	if len(receipts) > 50 {
		return
	}
	dir := filepath.Join(workDir, "windows-updates")
	unlock, err := securestate.Lock(dir)
	if err != nil {
		return
	}
	defer unlock()
	for _, value := range receipts {
		parts := strings.Split(value, "-")
		if len(parts) != 3 || !numeric.MatchString(parts[0]) || !numeric.MatchString(parts[1]) || !(digest.MatchString(parts[2]) || parts[2] == "closed") {
			continue
		}
		path := filepath.Join(dir, parts[0]+"-"+parts[1]+".json")
		var rec record
		if securestate.ReadJSON(path, &rec) != nil || rec.Task != parts[0] || rec.Ref != parts[1] || rec.Result == nil {
			continue
		}
		if parts[2] == "closed" {
			rec.Phase = "closed"
		} else if hashEvidence(rec.Result.ExecutionEvidence) != parts[2] {
			continue
		}
		rec.Receipt = parts[2]
		_ = securestate.WriteJSON(path, &rec)
	}
}
