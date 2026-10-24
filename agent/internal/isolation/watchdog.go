package isolation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

func watch(ctx context.Context, work, id string, m serviceManager, f firewall) (result error) {
	return watchWithClock(ctx, work, id, m, f, time.Now)
}

func watchWithClock(ctx context.Context, work, id string, m serviceManager, f firewall, clock func() time.Time) (result error) {
	unlock, err := securestate.Lock(directory(work))
	if err != nil {
		return err
	}
	l, err := readLease(work, id)
	if err != nil {
		// The immutable recovery identity is never rewritten by lease renewal.
		// Even a torn/corrupt mutable journal must not prevent owned-rule cleanup.
		l, err = readRecord(filepath.Join(directory(work), id, "identity.json"), id)
		if err != nil {
			unlock()
			return err
		}
		l.Phase = "restoring"
		l.Automatic = true
		l.Cause = "journal_unreadable"
	}
	cleaned := false
	// Keep an in-memory identity even if a record later becomes unreadable.
	// Native recovery retries the persisted cleanup after unexpected failure.
	defer func() {
		if !cleaned {
			result = errors.Join(result, f.clear(l))
		}
	}()
	now := clock()
	if l.Phase == "prepared" && now.Before(l.Deadline) && !now.Before(l.Created) {
		l.Phase = "applying"
		l.Message = "applying owned firewall rules"
		if err = save(work, l, now); err == nil {
			err = f.apply(l)
		}
		if err == nil && clock().Before(l.Deadline) {
			l.Phase = "active"
			l.Message = "waiting for authenticated post-isolation confirmation"
			err = save(work, l, clock())
		}
		if err != nil {
			l.Phase = "restoring"
			l.Automatic = true
			l.Cause = "apply_failed"
			l.Message = "isolation apply failed: " + err.Error()
			err = save(work, l, clock())
		}
	} else if l.Phase != "finished" {
		// A restarted owner cannot prove its previous rules/session survived.
		// Withdraw instead of reapplying or extending the original deadline.
		l.Phase = "restoring"
		l.Automatic = true
		if l.Cause == "" {
			l.Cause = "watchdog_restarted"
		}
		l.Message = "independent isolation watchdog restarted; withdrawing isolation"
		err = save(work, l, now)
	}
	unlock()
	if err != nil {
		return err
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	var revision uint64
	var deadline time.Time
	for {
		unlock, err = securestate.Lock(directory(work))
		if err != nil {
			return err
		}
		current, e := readLease(work, id)
		if e != nil {
			l.Phase = "restoring"
			l.Automatic = true
			l.Cause = "journal_unreadable"
			l.Message = "isolation journal unreadable; withdrawing owned firewall rules"
			if e = save(work, l, clock()); e != nil {
				unlock()
				return e
			}
			current = l
		}
		l = current
		now = clock()
		if l.Revision != revision {
			remaining := l.Deadline.Sub(now)
			if remaining > LeaseDuration {
				remaining = LeaseDuration
			}
			deadline = now.Add(remaining)
			revision = l.Revision
		}
		if l.Phase == "active" || l.Phase == "applying" || l.Phase == "prepared" {
			if !now.Before(deadline) || !now.Before(l.Deadline) || now.Before(l.Updated) || ctx.Err() != nil {
				l.Phase = "restoring"
				l.Automatic = true
				l.Cause = "lease_expired"
				l.Message = "authenticated isolation lease expired; withdrawing isolation"
				err = save(work, l, now)
			}
		}
		if err == nil && (l.Phase == "restoring" || l.Phase == "attention") {
			if e := f.clear(l); e != nil {
				l.Phase = "attention"
				l.Message = "isolation withdrawal failed; retrying: " + e.Error()
				err = save(work, l, now)
				var exit *ownerExitRequired
				if err == nil && errors.As(e, &exit) {
					err = e
				}
			} else {
				cleaned = true
				l.Phase = "finished"
				l.Restored = now
				if l.Automatic {
					l.Message = withdrawalMessage(l.Cause)
				} else {
					l.Message = "isolation withdrawn by operator"
				}
				err = save(work, l, now)
			}
		}
		finished := l.Phase == "finished"
		if finished && err == nil {
			if !cleaned {
				err = f.clear(l)
				cleaned = err == nil
			}
			if err == nil {
				err = retireWatchdogLocked(work, id, m)
			}
		}
		unlock()
		if err != nil {
			return err
		}
		if finished {
			return nil
		}
		// Keep retrying failed cleanup while the owner is running. On shutdown,
		// fail the service so the native recovery policy retries on next boot.
		if ctx.Err() != nil {
			return fmt.Errorf("isolation cleanup remains pending at service stop")
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
	}
}

func withdrawalMessage(cause string) string {
	switch cause {
	case "lease_expired":
		return "管理通道未在 10 秒内完成认证确认，已自动恢复网络"
	case "watchdog_restarted":
		return "隔离看护进程重启，已自动恢复网络"
	case "apply_failed":
		return "隔离规则未能完整生效，已撤销本次隔离"
	case "watchdog_startup_failed":
		return "隔离看护未能启动，已撤销本次隔离"
	case "journal_unreadable":
		return "隔离状态记录不可读，已清理本次隔离规则"
	default:
		return "本机安全保护已自动撤销隔离，网络已恢复"
	}
}

// Service retirement and a subsequent Begin share the same transaction lock.
// The caller holds it through the finished record and service removal.
// Without it an old owner's remove could delete a newly installed service after
// checking the previous unit contents. Never retire a different current lease.
func retireWatchdogLocked(work, id string, m serviceManager) error {
	current, err := Current(work)
	if err != nil {
		return err
	}
	if current.ID != id {
		return nil
	}
	if current.Phase != "finished" {
		return fmt.Errorf("cannot retire unfinished isolation recovery")
	}
	return m.remove(helperPath(work, id), work)
}
