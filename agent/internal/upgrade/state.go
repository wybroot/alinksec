package upgrade

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/v3/process"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

const startupTimeout = 60 * time.Second
const healthyPeriod = 5 * time.Second
const maxResults = 64

type transaction struct {
	ID              string    `json:"id"`
	CommandID       string    `json:"command_id"`
	Executable      string    `json:"executable"`
	OldHash         string    `json:"old_sha256"`
	NewHash         string    `json:"new_sha256"`
	Version         string    `json:"version"`
	OriginalPID     int       `json:"original_pid"`
	OriginalStarted int64     `json:"original_started"`
	Deadline        time.Time `json:"deadline"`
	Phase           string    `json:"phase"`
	ReadyPID        int       `json:"ready_pid,omitempty"`
	ReadyStarted    int64     `json:"ready_started,omitempty"`
	ReadyAt         time.Time `json:"ready_at,omitempty"`
	LastReadyAt     time.Time `json:"last_ready_at,omitempty"`
	ReadySession    uint64    `json:"ready_session,omitempty"`
}

// Outcome remains on disk across restarts and is replayed on each authenticated
// connection. A transport send is not a server acknowledgement of persistence.
type Outcome struct {
	ID         string    `json:"id"`
	CommandID  string    `json:"command_id"`
	Version    string    `json:"version"`
	Success    bool      `json:"success"`
	Complete   bool      `json:"complete"`
	RolledBack bool      `json:"rolled_back"`
	Message    string    `json:"message"`
	Time       time.Time `json:"time"`
}

func upgradeDir(workDir string) string { return filepath.Join(workDir, "upgrade") }
func statePath(workDir string) string  { return filepath.Join(upgradeDir(workDir), "state.json") }
func resultPath(workDir, id string) string {
	return filepath.Join(upgradeDir(workDir), "results", id+".json")
}

func privateDir(path string) error {
	return securestate.PrivateDir(path)
}

func readJSON(path string, value any) error {
	return securestate.ReadJSON(path, value)
}

func writeJSON(path string, value any) error {
	return securestate.WriteJSON(path, value)
}

func loadTransaction(workDir string) (*transaction, error) {
	var tx transaction
	if err := readJSON(statePath(workDir), &tx); err != nil {
		return nil, err
	}
	if !validID(tx.ID) || tx.CommandID == "" || len(tx.CommandID) > 256 || tx.Version == "" || len(tx.Version) > 128 || !filepath.IsAbs(tx.Executable) || tx.Executable != filepath.Clean(tx.Executable) || !validHash(tx.OldHash) || !validHash(tx.NewHash) || tx.OriginalPID <= 0 || tx.OriginalStarted <= 0 || tx.Deadline.IsZero() {
		return nil, fmt.Errorf("invalid upgrade transaction identity")
	}
	switch tx.Phase {
	case "prepared", "pending", "rollback", "finished":
	default:
		return nil, fmt.Errorf("invalid upgrade transaction phase")
	}
	return &tx, nil
}

func validID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && id == strings.ToLower(id)
}
func validHash(hash string) bool {
	b, e := hex.DecodeString(hash)
	return e == nil && len(b) == 32 && hash == strings.ToLower(hash)
}
func newID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func Outcomes(workDir string) ([]Outcome, error) {
	entries, err := os.ReadDir(filepath.Join(upgradeDir(workDir), "results"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(entries) > maxResults*2 {
		return nil, fmt.Errorf("upgrade result limit exceeded")
	}
	var out []Outcome
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".record-") {
			continue
		} // Interrupted atomic write; never a committed result.
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !validID(id) {
			return nil, fmt.Errorf("invalid upgrade result filename")
		}
		var r Outcome
		if err := readJSON(resultPath(workDir, id), &r); err != nil {
			return nil, err
		}
		if r.ID != id || r.CommandID == "" || r.Time.IsZero() {
			return nil, fmt.Errorf("invalid upgrade result identity")
		}
		out = append(out, r)
	}
	if len(out) > maxResults {
		return nil, fmt.Errorf("upgrade result limit exceeded")
	}
	return out, nil
}

// CommandState also prevents a server replay after the Agent process changed.
func CommandState(workDir, commandID string) (*Outcome, bool, error) {
	results, err := Outcomes(workDir)
	if err != nil {
		return nil, false, err
	}
	for _, r := range results {
		if r.CommandID == commandID {
			return &r, false, nil
		}
	}
	tx, err := loadTransaction(workDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return nil, tx.CommandID == commandID && tx.Phase != "finished", nil
}

// MarkReady is called only after initialization and a successful mTLS heartbeat
// send. Repeated calls do not move the stabilization window forward.
func MarkReady(workDir, version string, session uint64) error {
	if _, err := os.Lstat(statePath(workDir)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	unlock, err := lockUpgrade(workDir)
	if err != nil {
		return err
	}
	defer unlock()
	tx, err := loadTransaction(workDir)
	if err != nil {
		return err
	}
	if tx.Phase != "pending" {
		return nil
	}
	if tx.Version != version {
		return fmt.Errorf("upgraded Agent version does not match requested version")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	if exe != tx.Executable {
		return fmt.Errorf("upgraded Agent executable path changed")
	}
	started, err := processStarted(os.Getpid())
	if err != nil {
		return err
	}
	if tx.OriginalPID == os.Getpid() && tx.OriginalStarted == started {
		return nil
	}
	if tx.ReadyPID != os.Getpid() || tx.ReadyStarted != started || tx.ReadySession != session {
		if err := verifySHA256(exe, tx.NewHash); err != nil {
			return err
		}
		tx.ReadyPID, tx.ReadyAt = os.Getpid(), time.Now()
	}
	tx.ReadyStarted = started
	tx.ReadySession = session
	tx.LastReadyAt = time.Now()
	return writeJSON(statePath(workDir), tx)
}

func CandidatePending(workDir string) bool {
	tx, err := loadTransaction(workDir)
	if err != nil || tx.Phase != "pending" {
		return false
	}
	started, e := processStarted(os.Getpid())
	return e == nil && (tx.OriginalPID != os.Getpid() || tx.OriginalStarted != started)
}

func Disconnected(workDir string, session uint64) error {
	if !CandidatePending(workDir) {
		return nil
	}
	release, err := lockUpgrade(workDir)
	if err != nil {
		return err
	}
	defer release()
	tx, err := loadTransaction(workDir)
	if err != nil {
		return err
	}
	if tx.Phase != "pending" || tx.ReadyPID != os.Getpid() || tx.ReadySession != session {
		return nil
	}
	tx.ReadyPID = 0
	tx.ReadyAt = time.Time{}
	tx.LastReadyAt = time.Time{}
	return writeJSON(statePath(workDir), tx)
}

func processStarted(pid int) (int64, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, err
	}
	return p.CreateTime()
}
