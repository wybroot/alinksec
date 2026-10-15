package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeManager struct {
	process                int
	stops, starts, removes int
	stopErr, startErr      error
}

func (*fakeManager) verify(string) error           { return nil }
func (*fakeManager) install(string, string) error  { return nil }
func (m *fakeManager) remove(string, string) error { m.removes++; return nil }
func (m *fakeManager) pid() (int, error)           { return m.process, nil }
func (m *fakeManager) stop(string, string) error   { m.stops++; return m.stopErr }
func (m *fakeManager) start() error                { m.starts++; return m.startErr }

func seedTransaction(t *testing.T) (string, *transaction, *fakeManager) {
	t.Helper()
	work := t.TempDir()
	id := strings.Repeat("a", 32)
	for _, dir := range []string{upgradeDir(work), filepath.Join(upgradeDir(work), id), filepath.Join(upgradeDir(work), "results")} {
		if err := privateDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(work, "agent")
	if err := os.WriteFile(exe, []byte("new Agent"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe+".old", []byte("old Agent"), 0700); err != nil {
		t.Fatal(err)
	}
	oldHash, _ := fileSHA256(exe + ".old")
	newHash, _ := fileSHA256(exe)
	started, err := processStarted(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	tx := &transaction{ID: id, CommandID: "upgrade-command", Executable: exe, OldHash: oldHash, NewHash: newHash, Version: "test-version", OriginalPID: os.Getpid() + 10000, OriginalStarted: started, Deadline: time.Now().Add(time.Minute), Phase: "pending", ReadyPID: os.Getpid(), ReadyStarted: started, ReadyAt: time.Now().Add(-healthyPeriod), LastReadyAt: time.Now()}
	saveTransaction(t, work, tx)
	return work, tx, &fakeManager{process: os.Getpid()}
}
func saveTransaction(t *testing.T, work string, tx *transaction) {
	t.Helper()
	if err := writeJSON(statePath(work), tx); err != nil {
		t.Fatal(err)
	}
}
func outcome(t *testing.T, work string) Outcome {
	t.Helper()
	r, err := Outcomes(work)
	if err != nil || len(r) != 1 {
		t.Fatalf("outcomes=%v error=%v", r, err)
	}
	return r[0]
}

func TestWatchdogRequiresStableCurrentServiceIdentity(t *testing.T) {
	for _, kind := range []string{"healthy", "too-early", "different-pid", "reused-pid", "original-pid", "expired", "disconnected", "stale-heartbeat"} {
		t.Run(kind, func(t *testing.T) {
			work, tx, m := seedTransaction(t)
			now := time.Now()
			switch kind {
			case "too-early":
				tx.ReadyAt = now
			case "different-pid":
				m.process = 0
			case "reused-pid":
				tx.ReadyStarted--
			case "original-pid":
				tx.OriginalPID = tx.ReadyPID
			case "disconnected":
				tx.ReadyPID = 0
			case "stale-heartbeat":
				tx.LastReadyAt = now.Add(-3 * time.Second)
			case "expired":
				tx.Deadline = now.Add(-time.Second)
			}
			saveTransaction(t, work, tx)
			finished, err := watchStep(work, m, now)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "healthy" {
				if !finished || !outcome(t, work).Success || m.stops != 0 {
					t.Fatal("healthy candidate was not confirmed without restarting")
				}
				return
			}
			if kind == "expired" {
				if !finished || !outcome(t, work).RolledBack || m.starts != 1 {
					t.Fatal("expired candidate was accepted")
				}
				return
			}
			if finished {
				t.Fatal("unconfirmed candidate completed")
			}
		})
	}
}

func TestRollbackResumesEveryReplacementBoundary(t *testing.T) {
	for _, boundary := range []string{"before-backup", "between-renames", "candidate-installed", "candidate-moved-aside", "old-restored"} {
		t.Run(boundary, func(t *testing.T) {
			work, tx, m := seedTransaction(t)
			tx.Deadline = time.Now().Add(-time.Second)
			switch boundary {
			case "before-backup":
				os.Remove(tx.Executable)
				if err := os.Rename(tx.Executable+".old", tx.Executable); err != nil {
					t.Fatal(err)
				}
				tx.Phase = "prepared"
			case "between-renames":
				os.Remove(tx.Executable)
			case "candidate-moved-aside":
				if err := os.Rename(tx.Executable, tx.Executable+".bad"); err != nil {
					t.Fatal(err)
				}
				tx.Phase = "rollback"
			case "old-restored":
				os.Remove(tx.Executable)
				if err := os.Rename(tx.Executable+".old", tx.Executable); err != nil {
					t.Fatal(err)
				}
				tx.Phase = "rollback"
			}
			saveTransaction(t, work, tx)
			finished, err := watchStep(work, m, time.Now())
			if err != nil || !finished {
				t.Fatalf("finished=%v error=%v", finished, err)
			}
			if err := regularHash(tx.Executable, tx.OldHash); err != nil {
				t.Fatal(err)
			}
			r := outcome(t, work)
			if r.Success || !r.RolledBack || m.starts != 1 {
				t.Fatalf("false rollback outcome %+v", r)
			}
			state, err := loadTransaction(work)
			if err != nil || state.Phase != "finished" {
				t.Fatalf("unfinished recovery: %v %v", state, err)
			}
		})
	}
}

func TestRollbackRejectsUnexpectedFilesBeforeStoppingService(t *testing.T) {
	for _, kind := range []string{"corrupt-backup", "changed-candidate", "missing-backup"} {
		t.Run(kind, func(t *testing.T) {
			work, tx, m := seedTransaction(t)
			tx.Deadline = time.Now().Add(-time.Second)
			switch kind {
			case "corrupt-backup":
				os.WriteFile(tx.Executable+".old", []byte("unexpected"), 0700)
			case "changed-candidate":
				os.WriteFile(tx.Executable, []byte("unexpected"), 0700)
			case "missing-backup":
				os.Remove(tx.Executable + ".old")
			}
			saveTransaction(t, work, tx)
			finished, err := watchStep(work, m, time.Now())
			if err == nil || finished || m.stops != 0 || m.starts != 0 {
				t.Fatalf("unsafe mutation: finished=%v stops=%d starts=%d error=%v", finished, m.stops, m.starts, err)
			}
			r := outcome(t, work)
			if r.Success || r.RolledBack {
				t.Fatal("reported a rollback that never happened")
			}
			state, _ := loadTransaction(work)
			if state.Phase != "rollback" {
				t.Fatal("lost retryable rollback journal")
			}
		})
	}
}

func TestRollbackRetriesNativeServiceFailure(t *testing.T) {
	for _, stopFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "start", true: "stop"}[stopFailure], func(t *testing.T) {
			work, tx, m := seedTransaction(t)
			tx.Phase = "rollback"
			saveTransaction(t, work, tx)
			if stopFailure {
				m.stopErr = errors.New("cannot stop")
			} else {
				m.startErr = errors.New("cannot start")
			}
			if finished, err := watchStep(work, m, time.Now()); err == nil || finished {
				t.Fatal("native failure was hidden")
			}
			if r := outcome(t, work); r.Success || r.RolledBack {
				t.Fatal("failed restart reported success")
			}
			m.stopErr, m.startErr = nil, nil
			finished, err := watchStep(work, m, time.Now())
			if err != nil || !finished || !outcome(t, work).RolledBack {
				t.Fatalf("retry failed: %v", err)
			}
		})
	}
}

func TestMarkReadyBindsVersionExecutableAndDoesNotExtendWindow(t *testing.T) {
	work, tx, _ := seedTransaction(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	tx.Executable = exe
	tx.NewHash, err = fileSHA256(exe)
	if err != nil {
		t.Fatal(err)
	}
	tx.ReadyPID = 0
	tx.ReadyStarted = 0
	tx.ReadyAt = time.Time{}
	saveTransaction(t, work, tx)
	if err := MarkReady(work, "wrong-version", 1); err == nil {
		t.Fatal("accepted different product version")
	}
	if err := MarkReady(work, tx.Version, 1); err != nil {
		t.Fatal(err)
	}
	first, _ := loadTransaction(work)
	if err := MarkReady(work, tx.Version, 1); err != nil {
		t.Fatal(err)
	}
	second, _ := loadTransaction(work)
	defer func() {
		if err := Disconnected(work, 1); err != nil {
			t.Fatal(err)
		}
		disconnected, _ := loadTransaction(work)
		if disconnected.ReadyPID != 0 || !disconnected.ReadyAt.IsZero() {
			t.Fatal("disconnected session retained readiness")
		}
		if err := MarkReady(work, tx.Version, 2); err != nil {
			t.Fatal(err)
		}
		changed, _ := loadTransaction(work)
		if changed.ReadySession != 2 || !changed.ReadyAt.After(first.ReadyAt) {
			t.Fatal("new session reused old stabilization period")
		}
	}()
	if second.ReadyPID != os.Getpid() || second.ReadyAt.IsZero() || !first.ReadyAt.Equal(second.ReadyAt) {
		t.Fatal("readiness identity or stabilization changed")
	}
}

func TestUpgradeCommandSurvivesProcessRestart(t *testing.T) {
	work, tx, m := seedTransaction(t)
	if r, pending, err := CommandState(work, tx.CommandID); err != nil || r != nil || !pending {
		t.Fatalf("pending replay: %v %v %v", r, pending, err)
	}
	if _, err := watchStep(work, m, time.Now()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if r, pending, err := CommandState(work, tx.CommandID); err != nil || r == nil || !r.Success || pending {
			t.Fatal("terminal replay lost")
		}
	}
	if r, pending, err := CommandState(work, "different-command"); err != nil || r != nil || pending {
		t.Fatal("unrelated command matched")
	}
}

func TestUpgradeLockExcludesOtherProcessesAndBadRecordsFailClosed(t *testing.T) {
	work, tx, _ := seedTransaction(t)
	unlocked, err := lockUpgrade(work)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		release, e := lockUpgrade(work)
		if e == nil {
			release()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("transaction lock did not exclude another holder")
	case <-time.After(50 * time.Millisecond):
	}
	unlocked()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lock was not released")
	}
	tx.ID = "../escape"
	saveTransaction(t, work, tx)
	if _, err := loadTransaction(work); err == nil {
		t.Fatal("accepted an invalid record identity")
	}
}

func TestWatchdogCancellationKeepsRecoveryForNextBoot(t *testing.T) {
	work, _, m := seedTransaction(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := watch(ctx, work, m); err != nil {
		t.Fatal(err)
	}
	state, err := loadTransaction(work)
	if err != nil || state.Phase != "pending" || m.removes != 0 {
		t.Fatal("shutdown removed pending recovery")
	}
}

func TestVerifyHashRejectsMalformedExpectedDigestWithoutPanic(t *testing.T) {
	for _, hash := range []string{"", "a", "not-a-digest", strings.Repeat("A", 64)} {
		if err := verifySHA256("irrelevant", hash); err == nil {
			t.Fatalf("accepted %q", hash)
		}
	}
}

func TestCommittedSuccessCannotRollBackAfterJournalWriteInterruption(t *testing.T) {
	work, tx, m := seedTransaction(t)
	r := Outcome{ID: tx.ID, CommandID: tx.CommandID, Version: tx.Version, Success: true, Complete: true, Message: "already confirmed", Time: time.Now()}
	if err := writeJSON(resultPath(work, tx.ID), r); err != nil {
		t.Fatal(err)
	}
	tx.Deadline = time.Now().Add(-time.Hour)
	saveTransaction(t, work, tx)
	finished, err := watchStep(work, m, time.Now())
	if err != nil || !finished || m.stops != 0 || !outcome(t, work).Success {
		t.Fatal("committed healthy outcome was reversed")
	}
	state, _ := loadTransaction(work)
	if state.Phase != "finished" {
		t.Fatal("phase did not converge to committed outcome")
	}
}

func TestInterruptedResultTemporaryFileDoesNotHideCommittedResults(t *testing.T) {
	work, _, m := seedTransaction(t)
	if _, err := watchStep(work, m, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upgradeDir(work), "results", ".record-interrupted"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if !outcome(t, work).Success {
		t.Fatal("uncommitted temporary file hid final result")
	}
}
