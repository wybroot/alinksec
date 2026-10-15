package isolation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

type fakeManager struct{}

func (fakeManager) verify(string) error          { return nil }
func (fakeManager) install(string, string) error { return nil }
func (fakeManager) remove(string, string) error  { return nil }

type fakeFirewall struct {
	mu                          sync.Mutex
	applies, clears, failClears int
	applyErr                    error
}

func (f *fakeFirewall) apply(*Lease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	return f.applyErr
}
func (f *fakeFirewall) clear(*Lease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clears++
	if f.failClears > 0 {
		f.failClears--
		return errors.New("fixture firewall busy")
	}
	return nil
}
func fixtureLease(t *testing.T, phase string, remaining time.Duration) (string, *Lease) {
	t.Helper()
	work := t.TempDir()
	now := time.Now()
	id := "0123456789abcdef0123456789abcdef"
	for _, dir := range []string{filepath.Join(directory(work), "leases"), filepath.Join(directory(work), id)} {
		if err := securestate.PrivateDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	l := &Lease{ID: id, Generation: 1, Revision: 1, CommandID: "fixture-isolate", Phase: phase, Created: now.Add(-time.Second), Updated: now, Deadline: now.Add(remaining), IPs: []string{"192.0.2.10", "2001:db8::10"}, Port: 19443, Backends: testBackends()}
	for path, value := range map[string]any{leasePath(work, id): l, filepath.Join(directory(work), "current.json"): id, filepath.Join(directory(work), id, "identity.json"): l} {
		if err := securestate.WriteJSON(path, value); err != nil {
			t.Fatal(err)
		}
	}
	return work, l
}
func waitPhase(t *testing.T, work, phase string) *Lease {
	t.Helper()
	until := time.Now().Add(4 * time.Second)
	for {
		l, err := Current(work)
		if err == nil && l.Phase == phase {
			return l
		}
		if time.Now().After(until) {
			t.Fatalf("waiting for %s: lease=%+v err=%v", phase, l, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func awaitWatch(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("independent watcher failed to finish")
	}
}
func startWatch(t *testing.T, work string, l *Lease, f *fakeFirewall) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- watch(ctx, work, l.ID, fakeManager{}, f) }()
	return done
}
func TestAuthenticatedConfirmationAndOperatorWithdrawal(t *testing.T) {
	work, l := fixtureLease(t, "prepared", 2*time.Second)
	f := &fakeFirewall{}
	done := startWatch(t, work, l, f)
	active := waitPhase(t, work, "active")
	if !active.Confirmed.IsZero() {
		t.Fatal("local firewall apply was reported as authenticated success")
	}
	now := time.Now()
	if err := Confirm(work, "ffffffffffffffffffffffffffffffff", now); err == nil {
		t.Fatal("different lease renewed")
	}
	if err := Confirm(work, l.ID, now); err != nil {
		t.Fatal(err)
	}
	confirmed, err := Current(work)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed.Confirmed.Equal(now) || !confirmed.Deadline.Equal(now.Add(LeaseDuration)) {
		t.Fatalf("wrong confirmation/deadline: %+v", confirmed)
	}
	if err := Restore(work, "fixture-restore"); err != nil {
		t.Fatal(err)
	}
	awaitWatch(t, done)
	final := waitPhase(t, work, "finished")
	if final.Automatic || final.Confirmed.IsZero() || final.Restored.IsZero() || final.RestoreCommandID != "fixture-restore" {
		t.Fatalf("wrong operator result: %+v", final)
	}
	if err := Confirm(work, l.ID, time.Now()); err == nil {
		t.Fatal("finished lease resurrected")
	}
}
func TestUnconfirmedLeaseExpiresWithoutAgent(t *testing.T) {
	work, l := fixtureLease(t, "prepared", 350*time.Millisecond)
	f := &fakeFirewall{}
	done := startWatch(t, work, l, f)
	awaitWatch(t, done)
	final := waitPhase(t, work, "finished")
	if !final.Automatic || !final.Confirmed.IsZero() || final.Restored.IsZero() {
		t.Fatalf("unconfirmed isolation did not fail open: %+v", final)
	}
	if f.applies != 1 || f.clears < 1 {
		t.Fatalf("wrong firewall lifecycle: %+v", f)
	}
}
func TestRestartNeverReappliesActiveOrPartialIsolation(t *testing.T) {
	for _, phase := range []string{"active", "applying", "restoring", "attention"} {
		t.Run(phase, func(t *testing.T) {
			work, l := fixtureLease(t, phase, 8*time.Second)
			f := &fakeFirewall{}
			done := startWatch(t, work, l, f)
			awaitWatch(t, done)
			final := waitPhase(t, work, "finished")
			if f.applies != 0 || !final.Automatic {
				t.Fatalf("restart extended or reapplied isolation: %+v", final)
			}
		})
	}
}
func TestPartialApplyFailureIsWithdrawnAndCleanupRetries(t *testing.T) {
	work, l := fixtureLease(t, "prepared", 2*time.Second)
	f := &fakeFirewall{applyErr: errors.New("fixture second address-family failed"), failClears: 1}
	done := startWatch(t, work, l, f)
	attention := waitPhase(t, work, "attention")
	if !attention.Restored.IsZero() {
		t.Fatal("failed cleanup claimed restoration")
	}
	awaitWatch(t, done)
	if f.applies != 1 || f.clears < 2 {
		t.Fatalf("partial apply was not cleaned: %+v", f)
	}
	final := waitPhase(t, work, "finished")
	if !final.Automatic || !final.Confirmed.IsZero() {
		t.Fatalf("partial apply claimed success: %+v", final)
	}
}
func TestExpiredOrBackwardsClockConfirmationCannotRenew(t *testing.T) {
	work, l := fixtureLease(t, "active", time.Second)
	for _, now := range []time.Time{l.Deadline, l.Deadline.Add(time.Hour), l.Updated.Add(-time.Millisecond)} {
		if err := Confirm(work, l.ID, now); err == nil {
			t.Fatalf("invalid time renewed isolation: %s", now)
		}
	}
	current, err := Current(work)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Deadline.Equal(l.Deadline) || !current.Confirmed.IsZero() {
		t.Fatal("invalid confirmation mutated lease")
	}
}
func TestCorruptMutableJournalStillWithdrawsUsingRecoveryIdentity(t *testing.T) {
	work, l := fixtureLease(t, "active", 8*time.Second)
	if err := os.WriteFile(leasePath(work, l.ID), []byte("torn"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeFirewall{}
	done := startWatch(t, work, l, f)
	awaitWatch(t, done)
	final := waitPhase(t, work, "finished")
	if f.applies != 0 || f.clears < 1 || !final.Automatic {
		t.Fatalf("corrupt journal left isolation behind: %+v", final)
	}
}
func TestActiveConfirmedCommandRemainsHistoryAfterAutomaticRestoration(t *testing.T) {
	work, l := fixtureLease(t, "active", time.Second)
	l.Confirmed = time.Now().Add(-time.Millisecond)
	if err := securestate.WriteJSON(leasePath(work, l.ID), l); err != nil {
		t.Fatal(err)
	}
	f := &fakeFirewall{}
	done := startWatch(t, work, l, f)
	awaitWatch(t, done)
	result, err := CommandState(work, l.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Confirmed.IsZero() || result.Phase != "finished" || !result.Automatic {
		t.Fatalf("historical success or actual restoration lost: %+v", result)
	}
}

func TestRemovalExcludesNewLeaseTransactionsUntilAgentStops(t *testing.T) {
	work, _ := fixtureLease(t, "active", time.Second)
	if release, err := lockForRemoval(work, fakeManager{}); err == nil {
		release()
		t.Fatal("uninstall accepted an active isolation lease")
	}
	work, _ = fixtureLease(t, "finished", time.Second)
	release, err := lockForRemoval(work, fakeManager{})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	acquired := make(chan error, 1)
	go func() {
		unlock, err := securestate.Lock(directory(work))
		if err == nil {
			unlock()
		}
		acquired <- err
	}()
	select {
	case err := <-acquired:
		t.Fatal("new lease transaction entered during uninstall", err)
	case <-time.After(60 * time.Millisecond):
	}
	release()
	release() // Deferred release remains safe after the work directory is removed.
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease lock not released after service stop")
	}
}
