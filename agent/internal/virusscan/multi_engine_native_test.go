package virusscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/clamav"
	"github.com/alinksec/alinksec-agent/internal/clamav/clamavtest"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
)

func multiEngineFixture(t *testing.T, reply string, afterRead func() error) (*Engine, string, string, <-chan []byte, <-chan error) {
	t.Helper()
	cfg, version := yaratest.Native(t)
	input, outcome := make(chan []byte, 1), make(chan error, 1)
	transport := clamavtest.Start(t, func(conn net.Conn) {
		command, err := clamavtest.Command(conn)
		if err != nil {
			return
		}
		if command == "zVERSION\x00" {
			clamavtest.Reply(conn, clamVersion)
			return
		}
		if command != "zINSTREAM\x00" {
			return
		}
		data, err := clamavtest.Stream(conn)
		input <- data
		if err == nil {
			err = afterRead()
		}
		outcome <- err
		if err == nil {
			clamavtest.Reply(conn, reply)
		}
	})
	work := t.TempDir()
	engine := NewEngine(work, quietLogger())
	engine.SetClamAV(clamav.New(transport))
	engine.SetYARA(yara.New(cfg, configguard.ReadFile))
	return engine, work, version, input, outcome
}

func checkMultiEngineInput(t *testing.T, input <-chan []byte, outcome <-chan error, expected []byte) {
	t.Helper()
	select {
	case data := <-input:
		if !bytes.Equal(data, expected) {
			t.Fatal("ClamAV did not receive the complete expected bytes")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ClamAV fixture did not receive an input")
	}
	select {
	case err := <-outcome:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ClamAV fixture did not complete its file replacement")
	}
}

func TestNativeRealtimeEnginesKeepSnapshotAndWhitelistIdentity(t *testing.T) {
	before := []byte("harmless original ClamAV input")
	for _, sample := range []struct {
		name, reply, replacement, whitelist, engine string
		oldBuiltin, quarantined, clamFailure        bool
	}{
		{"clean-then-yara-with-old-hash-allowed", "stream: OK", yaratest.Marker, "old", "yara", true, true, false},
		{"clean-then-yara-with-new-hash-allowed", "stream: OK", yaratest.Marker, "new", "", true, false, false},
		{"failed-clamav-then-yara", "stream: ERROR", yaratest.Marker, "", "yara", true, true, true},
		{"later-clean-input-replaces-old-builtin-hit", "stream: OK", "different harmless clean input", "", "", true, false, false},
		{"clamav-hit-cannot-move-allowed-replacement", "stream: Harmless.Original FOUND", yaratest.Marker, "new", "clamav", false, false, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "marker")
			after := []byte(sample.replacement)
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			engine, work, version, input, outcome := multiEngineFixture(t, sample.reply, func() error {
				staged := path + ".next"
				if err := os.WriteFile(staged, after, 0600); err != nil {
					return err
				}
				return os.Rename(staged, path)
			})
			if sample.oldBuiltin {
				testDB(t, work, "old-snapshot-only", fmt.Sprintf("%x", sha256.Sum256(before)))
			}
			if sample.whitelist != "" {
				allowed := before
				if sample.whitelist == "new" {
					allowed = after
				}
				policy := fmt.Sprintf(`{"virus_realtime":{"enabled":true,"action":"quarantine"},"virus_whitelist":[{"type":"hash","value":"%x"}]}`, sha256.Sum256(allowed))
				if err := os.WriteFile(filepath.Join(work, "policy.json"), []byte(policy), 0600); err != nil {
					t.Fatal(err)
				}
			}
			finding := engine.CheckRealtime(path, work)
			checkMultiEngineInput(t, input, outcome, before)
			clamStatus, yaraStatus := engine.clamav.Status(), engine.yara.Status()
			if clamStatus.Scans != 1 || clamStatus.Failures != uint64(boolCount(sample.clamFailure)) || yaraStatus.Failures != 0 {
				t.Fatal("engine verdicts lost their independent accounting", clamStatus, yaraStatus)
			}
			wantYARA := uint64(1)
			if sample.engine == "clamav" {
				wantYARA = 0
			}
			if yaraStatus.Scans != wantYARA {
				t.Fatal("unexpected native YARA dispatch", yaraStatus)
			}
			if sample.engine == "" {
				if finding != nil {
					t.Fatal("later clean or whitelisted bytes reused an earlier verdict", finding)
				}
			} else {
				expected, engineVersion := after, version
				if sample.engine == "clamav" {
					expected, engineVersion = before, clamVersion
				}
				if finding == nil || finding.Path != path || finding.Engine != sample.engine || finding.EngineVersion != engineVersion || finding.Sha256 != fmt.Sprintf("%x", sha256.Sum256(expected)) || finding.Size != uint64(len(expected)) {
					t.Fatal("verdict mixed bytes or identity from another engine", finding)
				}
				if sample.engine == "yara" && (finding.Name != "AlinkSec_Native_Marker" || len(finding.MatchedRules) != 2) {
					t.Fatal("native finding lost rule evidence", finding)
				}
				if sample.quarantined {
					if finding.ActionTaken != "quarantined" || finding.QuarantineId == "" || finding.ActionError != "" {
						t.Fatal("replacement's own verdict did not authorize capture", finding)
					}
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatal("quarantine retained the original path", err)
					}
					if err := NewQuarantine(work).RestoreExpected(context.Background(), path, finding.QuarantineId, finding.Sha256); err != nil {
						t.Fatal(err)
					}
				} else if finding.ActionTaken != "alert_only" || finding.QuarantineId != "" || finding.ActionError != "file_identity_or_io_failure" {
					t.Fatal("old verdict acted on replacement bytes", finding)
				}
			}
			if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, after) {
				t.Fatal("replacement bytes were lost or changed", err)
			}
		})
	}
}

func TestNativeRealtimeFailedSecondReadCannotReplaceCompleteEvidence(t *testing.T) {
	before := []byte("harmless fully validated first snapshot")
	intermediate := []byte("harmless second snapshot before mutation")
	partial := []byte(yaratest.Marker)
	for _, signature := range []string{"complete", "partial"} {
		t.Run(signature, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "marker")
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			var secondRead, mutated atomic.Bool
			engine, work, _, input, outcome := multiEngineFixture(t, "stream: OK", func() error {
				if err := os.WriteFile(path, intermediate, 0600); err != nil {
					return err
				}
				secondRead.Store(true)
				return nil
			})
			matching := before
			if signature == "partial" {
				matching = partial
			}
			testDB(t, work, "independent-builtin", fmt.Sprintf("%x", sha256.Sum256(matching)))
			engine.SetIOBudget(func(context.Context, int) error {
				if secondRead.Load() && mutated.CompareAndSwap(false, true) {
					return os.WriteFile(path, partial, 0600)
				}
				return nil
			})
			finding := engine.CheckRealtime(path, work)
			checkMultiEngineInput(t, input, outcome, before)
			status := engine.yara.Status()
			if !mutated.Load() || status.Scans != 1 || status.Failures != 1 || status.ScanFailures.Counts["yara_read_failed_or_changed"] != 1 || engine.clamav.Status().Scans != 1 || engine.clamav.Status().Failures != 0 {
				t.Fatal("second engine accepted an incomplete changing input", status, engine.clamav.Status())
			}
			if signature == "complete" {
				if finding == nil || finding.Engine != "hash" || finding.EngineVersion != "" || finding.Path != path || finding.Sha256 != fmt.Sprintf("%x", sha256.Sum256(before)) || finding.Size != uint64(len(before)) || finding.ActionTaken != "alert_only" || finding.QuarantineId != "" || finding.ActionError != "file_identity_or_io_failure" {
					t.Fatal("independent builtin detection lost its complete snapshot or acted on changed bytes", finding)
				}
			} else if finding != nil {
				t.Fatal("incomplete second input authorized detection or action", finding)
			}
			if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, partial) {
				t.Fatal("failed second read altered or quarantined the replacement", err)
			}
		})
	}
}
