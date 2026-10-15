package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func helperPath(workDir, id string) string {
	name := "watchdog"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(upgradeDir(workDir), id, name)
}
func readyPath(workDir, id string) string {
	return filepath.Join(upgradeDir(workDir), id, "ready.json")
}

func candidatePath(tx *transaction) string { return tx.Executable + ".upgrade-" + tx.ID + ".new" }

// CheckRemoval prevents a concurrent uninstall from deleting the watchdog and
// then being undone when that watchdog restores/restarts the Agent.
func CheckRemoval(workDir string) error {
	if _, err := os.Lstat(statePath(workDir)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
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
	if tx.Phase != "finished" {
		return fmt.Errorf("Agent upgrade or rollback is pending; wait for completion before uninstall")
	}
	return (nativeManager{}).remove(helperPath(workDir, tx.ID), workDir)
}

func Pending(workDir string) bool {
	tx, err := loadTransaction(workDir)
	return err == nil && tx.Phase != "finished"
}

func watch(ctx context.Context, workDir string, m serviceManager) error {
	// The ready handshake precedes Apply's replacement; starting a native service
	// successfully does not by itself prove its recovery loop is running.
	tx, err := loadTransaction(workDir)
	if err != nil {
		return err
	}
	if err := writeJSON(readyPath(workDir, tx.ID), tx.ID); err != nil {
		return err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		} // Keep journal/service installed for reboot.
		finished, err := watchStep(workDir, m, time.Now())
		if err != nil {
			return err
		} // Native service recovery retries durable rollback.
		if finished {
			return m.remove(helperPath(workDir, tx.ID), workDir)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func watchStep(workDir string, m serviceManager, now time.Time) (bool, error) {
	unlock, err := lockUpgrade(workDir)
	if err != nil {
		return false, err
	}
	defer unlock()
	tx, err := loadTransaction(workDir)
	if err != nil {
		return false, err
	}
	if tx.Phase == "finished" {
		return true, nil
	}
	// The outcome is committed before phase=finished. A crash between those
	// writes must never turn an already confirmed success into a later rollback.
	var committed Outcome
	if err := readJSON(resultPath(workDir, tx.ID), &committed); err == nil && committed.ID == tx.ID && committed.CommandID == tx.CommandID && committed.Complete {
		tx.Phase = "finished"
		return true, writeJSON(statePath(workDir), tx)
	} else if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if tx.Phase == "pending" && tx.ReadyPID > 0 && !tx.ReadyAt.IsZero() && now.Before(tx.Deadline) && tx.LastReadyAt.Sub(tx.ReadyAt) >= healthyPeriod && now.Sub(tx.LastReadyAt) < 2500*time.Millisecond {
		pid, err := m.pid()
		if err != nil {
			return false, err
		}
		started, startErr := processStarted(pid)
		if startErr == nil && started == tx.ReadyStarted && pid == tx.ReadyPID && (pid != tx.OriginalPID || started != tx.OriginalStarted) {
			if err := verifySHA256(tx.Executable, tx.NewHash); err != nil {
				return false, err
			}
			return finish(workDir, tx, Outcome{Success: true, Message: "new Agent initialized, sent mTLS heartbeat and remained running"}, now)
		}
	}
	if tx.Phase != "rollback" && now.Before(tx.Deadline) {
		return false, nil
	}
	if tx.Phase != "rollback" {
		tx.Phase = "rollback"
		if err := writeJSON(statePath(workDir), tx); err != nil {
			return false, err
		}
	}
	if err := restorePrevious(tx, m); err != nil {
		// Keep phase=rollback and the independently installed service. Never claim
		// recovery succeeded when a file, stop, or start operation failed.
		r := Outcome{ID: tx.ID, CommandID: tx.CommandID, Version: tx.Version, Message: "automatic rollback requires attention: " + err.Error(), Time: now}
		if committed.Message == r.Message && !committed.Complete {
			return false, err
		}
		if e := writeJSON(resultPath(workDir, tx.ID), r); e != nil {
			return false, errors.Join(err, e)
		}
		return false, err
	}
	return finish(workDir, tx, Outcome{RolledBack: true, Message: "upgrade startup deadline expired; previous Agent restored and service restart requested"}, now)
}

func finish(workDir string, tx *transaction, r Outcome, now time.Time) (bool, error) {
	// A preparation interrupted before the renames can leave the verified staged
	// candidate behind. Remove only bytes belonging to this transaction.
	if err := regularHash(candidatePath(tx), tx.NewHash); err == nil {
		if err := os.Remove(candidatePath(tx)); err != nil {
			return false, err
		}
	}
	r.ID, r.CommandID, r.Version, r.Time = tx.ID, tx.CommandID, tx.Version, now
	r.Complete = true
	if err := writeJSON(resultPath(workDir, tx.ID), r); err != nil {
		return false, err
	}
	tx.Phase = "finished"
	return true, writeJSON(statePath(workDir), tx)
}

func regularHash(path, hash string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("upgrade executable is not a regular file: %s", path)
	}
	return verifySHA256(path, hash)
}

func restorePrevious(tx *transaction, m serviceManager) error {
	exe, old, bad := tx.Executable, tx.Executable+".old", tx.Executable+".bad-"+tx.ID
	// If power was lost after the old file was moved back, resume the restart
	// rather than requiring a backup that was already consumed.
	if err := regularHash(exe, tx.OldHash); err == nil {
		if err := m.stop(exe, tx.OldHash); err != nil {
			return err
		}
		return m.start()
	}
	if err := regularHash(old, tx.OldHash); err != nil {
		return fmt.Errorf("old Agent validation: %w", err)
	}
	if _, err := os.Lstat(exe); err == nil {
		if err := regularHash(exe, tx.NewHash); err != nil {
			return fmt.Errorf("refusing to replace an unexpectedly changed Agent: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := m.stop(exe, tx.NewHash); err != nil {
		return err
	}
	if _, err := os.Lstat(exe); err == nil {
		// Revalidate after stopping the candidate, before moving any files.
		if err := regularHash(exe, tx.NewHash); err != nil {
			return err
		}
		if info, err := os.Lstat(bad); err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("invalid failed candidate path")
			}
			if err := os.Remove(bad); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := moveExecutable(exe, bad); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := moveExecutable(old, exe); err != nil {
		return err
	}
	if err := regularHash(exe, tx.OldHash); err != nil {
		return err
	}
	return m.start()
}
