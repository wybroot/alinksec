package virusscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// Observe the blocked call instead of relying on a scheduling delay: the policy
// must change after this particular realtime check queues behind another scan.
func waitForQueuedRealtimeCheck(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(stack, "virusscan.(*Engine).CheckRealtime(") && strings.Contains(stack, "sync.(*Mutex).Lock(") {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("realtime check did not queue behind the scan lock")
}

func TestQueuedRealtimeCheckUsesCurrentPolicy(t *testing.T) {
	type policySnapshot struct {
		data string
		err  error
	}
	for _, tc := range []struct {
		name    string
		policy  policySnapshot
		wantHit bool
	}{
		{"disabled", policySnapshot{data: `{"virus_realtime":{"enabled":false,"action":"quarantine"}}`}, false},
		{"alert-only", policySnapshot{data: `{"virus_realtime":{"enabled":true,"action":"alert_only"}}`}, true},
		{"unreadable", policySnapshot{err: os.ErrPermission}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			path := filepath.Join(t.TempDir(), "harmless-queued.txt")
			data := []byte("harmless queued realtime policy fixture")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			testDB(t, work, "queued-policy", hex.EncodeToString(digest[:]))
			var policy atomic.Value
			policy.Store(policySnapshot{data: `{"virus_realtime":{"enabled":true,"action":"quarantine"}}`})
			engine := NewEngineWithPolicyReader(work, slog.New(slog.NewTextHandler(io.Discard, nil)), func() ([]byte, error) {
				snapshot := policy.Load().(policySnapshot)
				return []byte(snapshot.data), snapshot.err
			})
			reads := 0
			engine.SetIOBudget(func(context.Context, int) error { reads++; return nil })
			engine.mu.Lock()
			locked := true
			defer func() {
				if locked {
					engine.mu.Unlock()
				}
			}()
			result := make(chan *pb.VirusFinding, 1)
			go func() { result <- engine.CheckRealtime(path, work) }()
			waitForQueuedRealtimeCheck(t)
			policy.Store(tc.policy)
			engine.mu.Unlock()
			locked = false
			var finding *pb.VirusFinding
			select {
			case finding = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("queued realtime check did not finish")
			}
			if tc.wantHit {
				if finding == nil || finding.ActionTaken != "alert_only" || finding.QuarantineId != "" {
					t.Fatalf("queued check retained the earlier quarantine action: %+v", finding)
				}
			} else if finding != nil || reads != 0 {
				t.Fatalf("queued check ran after authorization was withdrawn: finding=%+v IO=%d", finding, reads)
			}
			if current, err := os.ReadFile(path); err != nil || string(current) != string(data) {
				t.Fatal("queued check moved or changed the file", err)
			}
			policy.Store(policySnapshot{data: `{"virus_realtime":{"enabled":true,"action":"alert_only"}}`})
			if finding := engine.CheckRealtime(path, work); finding == nil || finding.ActionTaken != "alert_only" {
				t.Fatal("restoring the policy did not restore realtime detection", finding)
			}
		})
	}
}

func TestInFlightRealtimeCheckRetainsAuthorizedAction(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(t.TempDir(), "harmless-in-flight.txt")
	data := []byte("harmless in-flight realtime policy fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	testDB(t, work, "in-flight-policy", hex.EncodeToString(digest[:]))
	var enabled atomic.Bool
	enabled.Store(true)
	engine := NewEngineWithPolicyReader(work, slog.New(slog.NewTextHandler(io.Discard, nil)), func() ([]byte, error) {
		if enabled.Load() {
			return []byte(`{"virus_realtime":{"enabled":true,"action":"alert_only"}}`), nil
		}
		return []byte(`{"virus_realtime":{"enabled":false,"action":"quarantine"}}`), nil
	})
	engine.SetIOBudget(func(context.Context, int) error { enabled.Store(false); return nil })
	if finding := engine.CheckRealtime(path, work); finding == nil || finding.ActionTaken != "alert_only" {
		t.Fatal("policy change discarded an already-started finding or replaced its action", finding)
	}
	if finding := engine.CheckRealtime(path, work); finding != nil {
		t.Fatal("next file ignored the disabled policy", finding)
	}
}

func TestRealtimeCheckKeepsWhitelistAndActionFromSamePolicy(t *testing.T) {
	for _, kind := range []string{"path", "hash"} {
		for _, unreadable := range []bool{false, true} {
			name := kind + "/updated"
			if unreadable {
				name = kind + "/unreadable"
			}
			t.Run(name, func(t *testing.T) {
				work := t.TempDir()
				path := filepath.Join(t.TempDir(), "harmless-policy-snapshot.txt")
				data := []byte("harmless policy snapshot fixture")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(data)
				hash := hex.EncodeToString(digest[:])
				testDB(t, work, "policy-snapshot", hash)
				value := hash
				if kind == "path" {
					value = filepath.Dir(path)
				}
				before, err := json.Marshal(map[string]any{
					"virus_realtime":  map[string]any{"enabled": true, "action": "quarantine"},
					"virus_whitelist": []whitelistEntry{{Type: kind, Value: value}},
				})
				if err != nil {
					t.Fatal(err)
				}
				after := []byte(`{"virus_realtime":{"enabled":true,"action":"alert_only"},"virus_whitelist":[]}`)
				current, currentErr := before, error(nil)
				replaceAfterRead := false
				engine := NewEngineWithPolicyReader(work, slog.New(slog.NewTextHandler(io.Discard, nil)), func() ([]byte, error) {
					// Each read is a valid snapshot, as with configguard.Store.Policy.
					// Commit the next policy immediately after returning the old copy.
					snapshot, err := append([]byte(nil), current...), currentErr
					if replaceAfterRead {
						replaceAfterRead = false
						current = after
						if unreadable {
							current, currentErr = nil, os.ErrPermission
						}
					}
					return snapshot, err
				})
				replaceAfterRead = true
				if finding := engine.CheckRealtime(path, work); finding != nil {
					t.Fatalf("mixed policy snapshots bypassed the authorized whitelist: %+v", finding)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
					t.Fatal("policy transition moved or changed the whitelisted file", err)
				}
				if unreadable {
					if finding := engine.CheckRealtime(path, work); finding != nil {
						t.Fatal("next file ignored the unavailable policy", finding)
					}
				}
				current, currentErr = after, nil
				finding := engine.CheckRealtime(path, work)
				if finding == nil || finding.Sha256 != hash || finding.ActionTaken != "alert_only" || finding.QuarantineId != "" {
					t.Fatal("next file did not use the updated policy after whitelist removal", finding)
				}
			})
		}
	}
}

func TestQueuedRealtimeCheckUsesCurrentWhitelist(t *testing.T) {
	for _, kind := range []string{"path", "hash"} {
		for _, adding := range []bool{true, false} {
			name := kind + "/remove"
			if adding {
				name = kind + "/add"
			}
			t.Run(name, func(t *testing.T) {
				work := t.TempDir()
				path := filepath.Join(t.TempDir(), "harmless-queued-whitelist.txt")
				data := []byte("harmless queued whitelist fixture")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(data)
				hash := hex.EncodeToString(digest[:])
				testDB(t, work, "queued-whitelist", hash)
				value := hash
				if kind == "path" {
					value = filepath.Dir(path)
				}
				allowed, err := json.Marshal(map[string]any{
					"virus_realtime":  map[string]any{"enabled": true, "action": "alert_only"},
					"virus_whitelist": []whitelistEntry{{Type: kind, Value: value}},
				})
				if err != nil {
					t.Fatal(err)
				}
				detect := []byte(`{"virus_realtime":{"enabled":true,"action":"alert_only"},"virus_whitelist":[]}`)
				before, after := allowed, detect
				if adding {
					before, after = detect, allowed
				}
				var policy atomic.Value
				policy.Store(before)
				engine := NewEngineWithPolicyReader(work, slog.New(slog.NewTextHandler(io.Discard, nil)), func() ([]byte, error) {
					return policy.Load().([]byte), nil
				})
				engine.mu.Lock()
				locked := true
				defer func() {
					if locked {
						engine.mu.Unlock()
					}
				}()
				result := make(chan *pb.VirusFinding, 1)
				go func() { result <- engine.CheckRealtime(path, work) }()
				waitForQueuedRealtimeCheck(t)
				policy.Store(after)
				engine.mu.Unlock()
				locked = false
				select {
				case finding := <-result:
					if adding {
						if finding != nil {
							t.Fatal("queued file ignored the added whitelist", finding)
						}
					} else if finding == nil || finding.Sha256 != hash || finding.ActionTaken != "alert_only" {
						t.Fatal("queued file retained the removed whitelist", finding)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("queued realtime check did not finish")
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
					t.Fatal("queued whitelist check moved or changed the file", err)
				}
			})
		}
	}
}
