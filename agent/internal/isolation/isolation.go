package isolation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

type serviceManager interface {
	verify(string) error
	install(string, string) error
	remove(string, string) error
}
type firewall interface {
	apply(*Lease) error
	clear(*Lease) error
}

// Some native APIs release their handle even when close fails. Process exit is
// then the only remaining reliable way to terminate the dynamic owner session.
type ownerExitRequired struct{ error }

func ExecutionContract() uint32 {
	exe, err := os.Executable()
	if err != nil {
		return 0
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil || (nativeManager{}).verify(exe) != nil {
		return 0
	}
	if _, err := prepareBackends(); err != nil {
		return 0
	}
	return 1
}

// Begin returns acceptance only. DONE requires a round trip after firewall apply.
func Begin(work, server, command, reason string) error {
	if command == "" || len(command) > 256 || len(reason) > 2048 {
		return fmt.Errorf("invalid isolation request")
	}
	work, err := canonicalWork(work)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(work, "isolated.json")); err == nil {
		return fmt.Errorf("legacy unbounded isolation must be restored before creating a native isolation lease")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	m := nativeManager{}
	if err := m.verify(exe); err != nil {
		return err
	}
	backends, err := prepareBackends()
	if err != nil {
		return err
	}
	host, portText, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("invalid isolation management endpoint")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid management port")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 32 {
		return fmt.Errorf("cannot resolve bounded management addresses")
	}
	var ips []string
	seen := map[netip.Addr]bool{}
	for _, a := range addresses {
		a = a.Unmap()
		if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("invalid management address")
		}
		if !seen[a] {
			ips = append(ips, a.String())
			seen[a] = true
		}
	}
	unlock, err := securestate.Lock(directory(work))
	if err != nil {
		return err
	}
	defer unlock()
	var generation uint64 = 1
	if previous, err := Current(work); err == nil {
		if previous.Phase != "finished" {
			return fmt.Errorf("isolation or withdrawal already pending")
		}
		generation = previous.Generation + 1
		if generation == 0 {
			return fmt.Errorf("isolation generation exhausted")
		}
		if err := m.remove(helperPath(work, previous.ID), work); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	leases, err := Outcomes(work)
	if err != nil {
		return err
	}
	if len(leases) >= maxLeases {
		return fmt.Errorf("isolation outcome archive is full; archive reviewed outcomes before removing them")
	}
	for _, l := range leases {
		if l.CommandID == command || l.RestoreCommandID == command {
			return fmt.Errorf("isolation command already completed")
		}
		if l.Phase == "finished" {
			// The small durable outcome remains. Retired executable snapshots are
			// disposable only after their service has been removed above.
			os.Remove(helperPath(work, l.ID))
			os.Remove(filepath.Join(directory(work), l.ID, "identity.json"))
			os.Remove(filepath.Join(directory(work), l.ID))
		}
	}
	id, err := NewNonce()
	if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Join(directory(work), "leases"), filepath.Join(directory(work), id)} {
		if err := securestate.PrivateDir(dir); err != nil {
			return err
		}
	}
	if err := copyHelper(exe, helperPath(work, id)); err != nil {
		return err
	}
	now := time.Now()
	l := &Lease{ID: id, Generation: generation, Revision: 1, CommandID: command, Reason: reason, Phase: "prepared", Created: now, Updated: now, Deadline: now.Add(LeaseDuration), IPs: ips, Port: uint16(port), Backends: backends, Message: "waiting for independent isolation watchdog"}
	if err := securestate.WriteJSON(filepath.Join(directory(work), id, "identity.json"), l); err != nil {
		return err
	}
	if err := securestate.WriteJSON(leasePath(work, id), l); err != nil {
		return err
	}
	if err := securestate.WriteJSON(filepath.Join(directory(work), "current.json"), id); err != nil {
		return err
	}
	if err := m.install(helperPath(work, id), work); err != nil {
		// Start may have succeeded before a later service-manager error. Never
		// erase its journal or assume that no firewall operation took place.
		l.Phase = "restoring"
		l.Automatic = true
		l.Cause = "watchdog_startup_failed"
		l.Message = "watchdog startup failed; isolation withdrawal required: " + err.Error()
		if e := save(work, l, time.Now()); e != nil {
			return errors.Join(err, e)
		}
		return err
	}
	return nil
}

// Recover retries an interrupted service installation at Agent startup. It
// preserves the persisted deadline; the owner decides whether to apply or clear.
func Recover(work string) error {
	work, err := canonicalWork(work)
	if err != nil {
		return err
	}
	l, err := Current(work)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if l.Phase == "finished" {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	m := nativeManager{}
	if err := m.verify(exe); err != nil {
		return err
	}
	unlock, err := securestate.Lock(directory(work))
	if err != nil {
		return err
	}
	defer unlock()
	l, err = Current(work)
	if err != nil {
		return err
	}
	if l.Phase == "finished" {
		return nil
	}
	return m.install(helperPath(work, l.ID), work)
}
func copyHelper(source, target string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 128<<20 {
		return fmt.Errorf("invalid isolation watchdog executable")
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(f, 128<<20+1))
	if err == nil && n != info.Size() {
		err = fmt.Errorf("watchdog executable changed while copying")
	}
	if err == nil {
		err = out.Sync()
	}
	if e := out.Close(); err == nil {
		err = e
	}
	if err != nil {
		os.Remove(target)
		return err
	}
	return securestate.SyncDirectory(filepath.Dir(target))
}

func canonicalWork(work string) (string, error) {
	abs, err := filepath.Abs(work)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// LockForRemoval excludes new leases until the caller has stopped the Agent.
// Release before deleting the work directory (Windows cannot delete a held lock).
// Stopping the native Agent must succeed before release and directory deletion.
func LockForRemoval(work string) (func(), error) {
	return lockForRemoval(work, nativeManager{})
}
func lockForRemoval(work string, manager serviceManager) (func(), error) {
	work, err := canonicalWork(work)
	if err != nil {
		return nil, err
	}
	unlock, err := securestate.Lock(directory(work))
	if err != nil {
		return nil, err
	}
	var once sync.Once
	release := func() { once.Do(unlock) }
	l, err := Current(work)
	if errors.Is(err, os.ErrNotExist) {
		return release, nil
	}
	if err == nil && l.Phase != "finished" {
		err = fmt.Errorf("withdraw host isolation and wait for confirmed cleanup before uninstall")
	}
	if err == nil {
		err = manager.remove(helperPath(work, l.ID), work)
	}
	if err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func RunWatchdog(work, id string) error {
	if !validID(id) {
		return fmt.Errorf("invalid isolation watchdog identity")
	}
	return runWatchdogService(func(ctx context.Context) error { return watch(ctx, work, id, nativeManager{}, newFirewall()) })
}
