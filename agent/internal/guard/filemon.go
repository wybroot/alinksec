package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

type fileBaseline struct {
	Exists   bool   `json:"exists"`
	SHA256   string `json:"sha256"`
	Mode     uint32 `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Parent   string `json:"parent"`
	ParentID string `json:"parent_id"`
}

type fileObservation struct {
	kind string
	fileBaseline
	data []byte
}

type watchedFile struct {
	rule       config.FileRule
	path       string
	key        string
	baseline   *fileBaseline
	lastChange string
}

type fileMonitor struct {
	mu    sync.Mutex
	dir   string
	log   *slog.Logger
	files map[string]*watchedFile
}

func newFileMonitor(workDir string, log *slog.Logger) *fileMonitor {
	return &fileMonitor{dir: filepath.Join(workDir, "file-protection"), log: log, files: map[string]*watchedFile{}}
}

func platformMatches(platforms []string) bool {
	return len(platforms) == 0 || slices.Contains(platforms, runtime.GOOS)
}

func (m *fileMonitor) update(rules []config.FileRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := map[string]*watchedFile{}
	for _, rule := range rules {
		for _, path := range rule.Match.Paths {
			if !filepath.IsAbs(path) || !platformMatches(rule.Match.Platforms) {
				continue
			}
			path = filepath.Clean(path)
			sum := sha256.Sum256([]byte(rule.ID + "\x00" + path))
			key := hex.EncodeToString(sum[:])
			if !rule.Enabled {
				_ = os.Remove(filepath.Join(m.dir, key+".json"))
				_ = os.Remove(filepath.Join(m.dir, key+".bin"))
				continue
			}
			watch := m.files[key]
			if watch == nil {
				watch = &watchedFile{path: path, key: key}
			}
			watch.rule = rule
			next[key] = watch
		}
	}
	for key := range m.files {
		if next[key] == nil {
			_ = os.Remove(filepath.Join(m.dir, key+".json"))
			_ = os.Remove(filepath.Join(m.dir, key+".bin"))
		}
	}
	m.files = next
}

func (m *fileMonitor) check() []*pb.RptSecurityEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var events []*pb.RptSecurityEvent
	for _, watch := range m.files {
		if event := m.checkFile(watch); event != nil {
			events = append(events, event)
		}
	}
	return events
}

func (m *fileMonitor) checkFile(w *watchedFile) *pb.RptSecurityEvent {
	parent := filepath.Dir(w.path)
	canonical, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return m.fileEvent(w, "parent_unavailable", fileObservation{}, "alert_only", err)
	}
	if w.baseline == nil {
		data, readErr := readPrivateLimited(filepath.Join(m.dir, w.key+".json"), 8192)
		if readErr == nil {
			var baseline fileBaseline
			if json.Unmarshal(data, &baseline) != nil || !filepath.IsAbs(baseline.Parent) || (runtime.GOOS == "linux" && baseline.ParentID == "") || (baseline.Exists && len(baseline.SHA256) != 64) {
				return m.fileEvent(w, "baseline_invalid", fileObservation{}, "alert_only", fmt.Errorf("文件基准无效"))
			}
			w.baseline = &baseline
		} else if !os.IsNotExist(readErr) {
			return m.fileEvent(w, "baseline_unavailable", fileObservation{}, "alert_only", readErr)
		}
	}
	if w.baseline != nil && canonical != w.baseline.Parent {
		action := "alert_only"
		if hasAction(w.rule.Actions, "restore") {
			action = "restore_failed"
		}
		return m.fileEvent(w, "parent_changed", fileObservation{}, action, fmt.Errorf("父目录位置发生变化，拒绝恢复到新位置"))
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return m.fileEvent(w, "parent_unavailable", fileObservation{}, "alert_only", err)
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return m.fileEvent(w, "parent_unavailable", fileObservation{}, "alert_only", err)
	}
	info, err := directory.Stat()
	directory.Close()
	if err != nil {
		return m.fileEvent(w, "parent_unavailable", fileObservation{}, "alert_only", err)
	}
	parentID := directoryIdentity(info)
	if w.baseline != nil && parentID != w.baseline.ParentID {
		action := "alert_only"
		if hasAction(w.rule.Actions, "restore") {
			action = "restore_failed"
		}
		return m.fileEvent(w, "parent_changed", fileObservation{}, action, fmt.Errorf("父目录身份发生变化，拒绝恢复到新目录"))
	}
	current, err := observeFile(root, filepath.Base(w.path), w.rule.Match.Limit())
	if err != nil {
		return m.fileEvent(w, "read_failed", current, "alert_only", err)
	}
	if w.baseline == nil {
		if current.kind != "regular" && current.kind != "missing" {
			return m.fileEvent(w, "baseline_unavailable", current, "alert_only", fmt.Errorf("基准对象需要普通文件或缺失路径"))
		}
		current.Parent = canonical
		current.ParentID = parentID
		if err := m.saveBaseline(w, current); err != nil {
			return m.fileEvent(w, "baseline_save_failed", current, "alert_only", err)
		}
		baseline := current.fileBaseline
		w.baseline = &baseline
		return nil
	}
	base := w.baseline
	unchanged := !base.Exists && current.kind == "missing"
	if base.Exists && current.kind == "regular" {
		unchanged = base.SHA256 == current.SHA256 && base.Mode == current.Mode && base.UID == current.UID && base.GID == current.GID
	}
	if unchanged {
		w.lastChange = ""
		return nil
	}
	change := current.kind
	if current.kind == "regular" {
		switch {
		case !base.Exists:
			change = "created"
		case current.SHA256 != base.SHA256:
			change = "content_changed"
		default:
			change = "metadata_changed"
		}
	}
	action := "alert_only"
	if hasAction(w.rule.Actions, "restore") {
		if err = m.restoreFile(w, root); err != nil {
			action = "restore_failed"
		} else {
			action = "restored"
		}
	}
	return m.fileEvent(w, change, current, action, err)
}

func observeFile(root *os.Root, name string, limit int64) (fileObservation, error) {
	o := fileObservation{kind: "missing", fileBaseline: fileBaseline{UID: -1, GID: -1}}
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return o, nil
	}
	if err != nil {
		return o, err
	}
	o.Exists = true
	if info.Mode()&os.ModeSymlink != 0 {
		o.kind = "symlink"
		return o, nil
	}
	if !info.Mode().IsRegular() {
		o.kind = "non_regular"
		return o, nil
	}
	o.kind = "regular"
	o.Mode = uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
	o.UID, o.GID = fileOwner(info)
	if info.Size() > limit {
		o.kind = "oversized"
		return o, nil
	}
	f, err := root.Open(name)
	if err != nil {
		return o, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return o, fmt.Errorf("读取时文件身份发生变化")
	}
	o.data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return o, err
	}
	final, err := f.Stat()
	if err != nil || int64(len(o.data)) > limit || final.Size() != info.Size() || !final.ModTime().Equal(info.ModTime()) {
		return o, fmt.Errorf("读取时文件发生变化或超过上限")
	}
	sum := sha256.Sum256(o.data)
	o.SHA256 = hex.EncodeToString(sum[:])
	return o, nil
}

func (m *fileMonitor) saveBaseline(w *watchedFile, current fileObservation) error {
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return err
	}
	if current.Exists {
		if err := writePrivateAtomic(filepath.Join(m.dir, w.key+".bin"), current.data); err != nil {
			return err
		}
	}
	data, err := json.Marshal(current.fileBaseline)
	if err != nil {
		return err
	}
	return writePrivateAtomic(filepath.Join(m.dir, w.key+".json"), data)
}

func writePrivateAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".alinksec-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func readPrivateLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("防护状态文件类型或大小无效")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("防护状态文件超过大小上限")
	}
	return data, err
}

func (m *fileMonitor) restoreFile(w *watchedFile, root *os.Root) error {
	name := filepath.Base(w.path)
	if !w.baseline.Exists {
		return root.Remove(name)
	}
	data, err := readPrivateLimited(filepath.Join(m.dir, w.key+".bin"), w.rule.Match.Limit())
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) > w.rule.Match.Limit() || hex.EncodeToString(sum[:]) != w.baseline.SHA256 {
		return fmt.Errorf("基准内容校验失败，拒绝恢复")
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	temporary := ".alinksec-restore-" + w.key[:16] + fmt.Sprint(time.Now().UnixNano())
	f, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	if _, err = f.Write(data); err == nil && w.baseline.UID >= 0 {
		err = f.Chown(w.baseline.UID, w.baseline.GID)
	}
	if err == nil {
		err = f.Chmod(os.FileMode(w.baseline.Mode))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return replaceProtectedFile(dir, temporary, name)
}

func (m *fileMonitor) fileEvent(w *watchedFile, change string, current fileObservation, action string, err error) *pb.RptSecurityEvent {
	detail := map[string]any{"path": w.path, "change": change, "current_sha256": current.SHA256, "current_mode": current.Mode}
	if w.baseline != nil {
		detail["baseline_sha256"] = w.baseline.SHA256
		detail["baseline_mode"] = w.baseline.Mode
	}
	if err != nil {
		detail["error"] = err.Error()
	}
	encoded, _ := json.Marshal(detail)
	key := string(encoded) + ":" + action
	if key == w.lastChange {
		return nil
	}
	w.lastChange = key
	return &pb.RptSecurityEvent{RuleId: w.rule.ID, RuleName: w.rule.Name, Type: "file_tamper", Severity: processSeverity(w.rule.Severity), Detail: string(encoded), ActionTaken: action, EventTs: time.Now().UnixMilli()}
}
