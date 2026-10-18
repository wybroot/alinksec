//go:build windows

package windowslogin

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

type filterSession struct {
	session *wf.Session
	timer   *time.Timer
	block   Block
}
type nativeFirewall struct {
	mu       sync.Mutex
	sessions map[string]*filterSession
	failed   bool
}

func newFirewall() Firewall { return &nativeFirewall{sessions: map[string]*filterSession{}} }
func (f *nativeFirewall) Apply(b Block) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed {
		return fmt.Errorf("WFP cleanup requires process exit")
	}
	ip, err := netip.ParseAddr(b.IP)
	if err != nil || !safeSource(ip) || len(b.Ports) == 0 || len(b.Ports) > 16 || b.Expires <= time.Now().UnixMilli() || b.Expires-time.Now().UnixMilli() > 3600000 {
		return fmt.Errorf("invalid source block")
	}
	if old := f.sessions[b.Key]; old != nil {
		if old.block.Expires == b.Expires && slices.Equal(old.block.Ports, b.Ports) {
			return nil
		}
		if err := f.removeLocked(b.Key); err != nil {
			return err
		}
	}
	s, err := wf.New(&wf.Options{Name: "ALinkSec Windows login", Description: "Temporary remote source TCP restriction", Dynamic: true, TransactionStartTimeout: time.Second})
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		if err := s.Close(); err != nil {
			f.failed = true
			return fmt.Errorf("%w; cleanup: %v", cause, err)
		}
		return cause
	}
	guid, err := windows.GenerateGUID()
	if err != nil {
		return cleanup(err)
	}
	sub := wf.SublayerID(guid)
	if err = s.AddSublayer(&wf.Sublayer{ID: sub, Name: "ALinkSec Windows login", Weight: 65534}); err != nil {
		return cleanup(err)
	}
	layer := wf.LayerALEAuthRecvAcceptV6
	if ip.Is4() {
		layer = wf.LayerALEAuthRecvAcceptV4
	}
	for _, port := range b.Ports {
		if port < 1 || port > 65535 {
			return cleanup(fmt.Errorf("invalid TCP port"))
		}
		id, err := windows.GenerateGUID()
		if err != nil {
			return cleanup(err)
		}
		err = s.AddRule(&wf.Rule{ID: wf.RuleID(id), Name: "ALinkSec Windows login", Layer: layer, Sublayer: sub, Weight: 1, Action: wf.ActionBlock, HardAction: true, Conditions: []*wf.Match{
			{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: ip},
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: uint8(wf.IPProtoTCP)},
			{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(port)},
		}})
		if err != nil {
			return cleanup(err)
		}
	}
	entry := &filterSession{session: s, block: b}
	f.sessions[b.Key] = entry
	// Independent of the event reader/guard loop and its locks. Monotonic timers
	// also prevent a wall-clock rollback from extending an installed block.
	entry.timer = time.AfterFunc(time.Until(time.UnixMilli(b.Expires)), func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.sessions[b.Key] == entry {
			_ = f.removeLocked(b.Key)
		}
	})
	return nil
}
func (f *nativeFirewall) removeLocked(key string) error {
	old := f.sessions[key]
	if old == nil {
		return nil
	}
	if old.timer != nil {
		old.timer.Stop()
	}
	delete(f.sessions, key)
	if err := old.session.Close(); err != nil {
		f.failed = true
		return err
	}
	return nil
}
func (f *nativeFirewall) Remove(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed {
		return fmt.Errorf("WFP cleanup requires process exit")
	}
	return f.removeLocked(key)
}
func (f *nativeFirewall) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result error
	for k := range f.sessions {
		if err := f.removeLocked(k); err != nil {
			result = err
		}
	}
	return result
}
func (f *nativeFirewall) Active() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions), f.failed
}
