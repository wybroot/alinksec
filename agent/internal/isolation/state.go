// Package isolation implements short, authenticated isolation leases. The
// independent native service owns firewall changes; the Agent only requests and
// renews leases. Losing either process must never create permanent isolation.
package isolation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

const LeaseDuration = 10 * time.Second
const maxLeases = 64
const serviceName = "alinksec-agent-isolation-watchdog"

// Lease is also the durable outcome. A confirmed command remains successful
// history when later disconnection restores networking; Phase is current state.
type Lease struct {
	ID               string    `json:"id"`
	Generation       uint64    `json:"generation"`
	Revision         uint64    `json:"revision"`
	CommandID        string    `json:"command_id"`
	RestoreCommandID string    `json:"restore_command_id,omitempty"`
	Reason           string    `json:"reason"`
	Phase            string    `json:"phase"`
	Created          time.Time `json:"created"`
	Updated          time.Time `json:"updated"`
	Deadline         time.Time `json:"deadline"`
	Confirmed        time.Time `json:"confirmed,omitempty"`
	Restored         time.Time `json:"restored,omitempty"`
	Automatic        bool      `json:"automatic"`
	Message          string    `json:"message"`
	Cause            string    `json:"cause,omitempty"`
	IPs              []string  `json:"ips"`
	Port             uint16    `json:"port"`
	Backends         []string  `json:"backends"`
}

func directory(work string) string      { return filepath.Join(work, "isolation") }
func leasePath(work, id string) string  { return filepath.Join(directory(work), "leases", id+".json") }
func helperPath(work, id string) string { return filepath.Join(directory(work), id, helperName) }
func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && id == strings.ToLower(id)
}
func NewNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func readLease(work, id string) (*Lease, error) { return readRecord(leasePath(work, id), id) }
func readRecord(path, id string) (*Lease, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid isolation lease identity")
	}
	var l Lease
	if err := securestate.ReadJSON(path, &l); err != nil {
		return nil, err
	}
	if l.ID != id || l.CommandID == "" || len(l.CommandID) > 256 || len(l.RestoreCommandID) > 256 || len(l.Reason) > 2048 || l.Generation == 0 || l.Revision == 0 || l.Created.IsZero() || l.Updated.Before(l.Created) || l.Deadline.IsZero() || len(l.IPs) == 0 || len(l.IPs) > 32 || l.Port == 0 || len(l.Backends) > 2 {
		return nil, fmt.Errorf("invalid isolation lease record")
	}
	for _, ip := range l.IPs {
		a, err := netip.ParseAddr(ip)
		if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return nil, fmt.Errorf("invalid isolation management address")
		}
	}
	if l.Deadline.Sub(l.Updated) > LeaseDuration || l.Deadline.Before(l.Created) {
		return nil, fmt.Errorf("invalid isolation deadline")
	}
	switch l.Phase {
	case "prepared", "applying", "active", "restoring", "attention", "finished":
	default:
		return nil, fmt.Errorf("invalid isolation phase")
	}
	if err := validateBackends(l.Backends); err != nil {
		return nil, err
	}
	return &l, nil
}
func Current(work string) (*Lease, error) {
	var id string
	if err := securestate.ReadJSON(filepath.Join(directory(work), "current.json"), &id); err != nil {
		return nil, err
	}
	return readLease(work, id)
}
func save(work string, l *Lease, now time.Time) error {
	l.Revision++
	// Preserve detection of a backwards clock instead of writing an invalid time.
	if now.After(l.Updated) {
		l.Updated = now
	}
	return securestate.WriteJSON(leasePath(work, l.ID), l)
}
func Outcomes(work string) ([]Lease, error) {
	entries, err := os.ReadDir(filepath.Join(directory(work), "leases"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(entries) > 2*maxLeases {
		return nil, fmt.Errorf("isolation outcome archive exceeds limit")
	}
	var out []Lease
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".record-") {
			continue
		}
		l, err := readLease(work, strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	if len(out) > maxLeases {
		return nil, fmt.Errorf("isolation outcome archive exceeds limit")
	}
	return out, nil
}
func CommandState(work, command string) (*Lease, error) {
	leases, err := Outcomes(work)
	if err != nil {
		return nil, err
	}
	for _, l := range leases {
		if l.CommandID == command || l.RestoreCommandID == command {
			return &l, nil
		}
	}
	return nil, nil
}

// Confirm must only be called after consuming a fresh nonce on the very same
// authenticated stream that sent it. Expiration is irreversible for a lease.
func Confirm(work, id string, now time.Time) error {
	unlock, err := securestate.Lock(directory(work))
	if err != nil {
		return err
	}
	defer unlock()
	l, err := Current(work)
	if err != nil {
		return err
	}
	if l.ID != id || l.Phase != "active" || !now.Before(l.Deadline) || now.Before(l.Updated) {
		return fmt.Errorf("isolation lease is no longer renewable")
	}
	if l.Confirmed.IsZero() {
		l.Confirmed = now
	}
	l.Deadline = now.Add(LeaseDuration)
	return save(work, l, now)
}

// Restore only asks the independent owner to withdraw. Completion is reported
// after the firewall has actually been cleared, including partial apply errors.
func Restore(work, command string) error {
	if len(command) > 256 {
		return fmt.Errorf("invalid restore command")
	}
	unlock, err := securestate.Lock(directory(work))
	if err != nil {
		return err
	}
	defer unlock()
	l, err := Current(work)
	if err != nil {
		return err
	}
	if l.RestoreCommandID != "" && l.RestoreCommandID != command && l.Phase != "finished" {
		return fmt.Errorf("isolation restoration already pending")
	}
	if l.Phase == "finished" {
		return nil
	}
	l.RestoreCommandID = command
	l.Phase = "restoring"
	l.Automatic = false
	l.Cause = "operator_requested"
	l.Message = "operator requested isolation withdrawal"
	return save(work, l, time.Now())
}
