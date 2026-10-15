//go:build windows

package isolation

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

const helperName = "watchdog.exe"

type nativeFirewall struct {
	session    *wf.Session
	closeError error
}

func newFirewall() firewall              { return &nativeFirewall{} }
func prepareBackends() ([]string, error) { return []string{"wfp-dynamic-v1"}, nil }
func validateBackends(backends []string) error {
	if len(backends) != 1 || backends[0] != "wfp-dynamic-v1" {
		return fmt.Errorf("invalid Windows isolation backend")
	}
	return nil
}
func (f *nativeFirewall) apply(l *Lease) error {
	if err := validateBackends(l.Backends); err != nil {
		return err
	}
	if f.session != nil {
		return fmt.Errorf("isolation firewall session already active")
	}
	s, err := wf.New(&wf.Options{Name: "ALinkSec isolation " + l.ID, Description: "Independently withdrawn ten-second management lease", Dynamic: true, TransactionStartTimeout: time.Second})
	if err != nil {
		return err
	}
	f.session = s
	id, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	sub := wf.SublayerID(id)
	if err := s.AddSublayer(&wf.Sublayer{ID: sub, Name: "ALinkSec isolation " + l.ID, Weight: 65535}); err != nil {
		return err
	}
	add := func(layer wf.LayerID, weight uint64, action wf.Action, conditions ...*wf.Match) error {
		if !time.Now().Before(l.Deadline) {
			return fmt.Errorf("isolation lease expired during WFP apply")
		}
		id, err := windows.GenerateGUID()
		if err != nil {
			return err
		}
		return s.AddRule(&wf.Rule{ID: wf.RuleID(id), Name: "ALinkSec isolation " + l.ID, Layer: layer, Sublayer: sub, Weight: weight, Action: action, HardAction: action == wf.ActionBlock, Conditions: conditions})
	}
	layers := []struct {
		layer wf.LayerID
		ipv4  bool
	}{{wf.LayerALEAuthConnectV4, true}, {wf.LayerALEAuthRecvAcceptV4, true}, {wf.LayerALEAuthConnectV6, false}, {wf.LayerALEAuthRecvAcceptV6, false}}
	// Permits are soft: administrator deny rules still apply. Catch-all blocks
	// are hard and take precedence over ordinary allow rules in other sublayers.
	// Stage every exception before adding any deny; failure closes this session.
	for _, entry := range layers {
		if err := add(entry.layer, 100, wf.ActionPermit, &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: uint32(wf.ConditionFlagIsLoopback)}); err != nil {
			return err
		}
		for _, ip := range l.IPs {
			a, _ := netip.ParseAddr(ip)
			if a.Is4() != entry.ipv4 {
				continue
			}
			if err := add(entry.layer, 90, wf.ActionPermit, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: a}, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: uint8(wf.IPProtoTCP)}, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: l.Port}); err != nil {
				return err
			}
		}
	}
	for _, entry := range layers {
		if err := add(entry.layer, 1, wf.ActionBlock); err != nil {
			return err
		}
	}
	return nil
}
func (f *nativeFirewall) clear(l *Lease) error {
	if f.closeError != nil {
		return f.closeError
	}
	if f.session == nil {
		return nil
	} // Restarted dynamic sessions have no surviving filters.
	s := f.session
	f.session = nil
	// wf.Close releases its native handle even on error. Return failure so the
	// service exits and Windows tears down any remaining dynamic objects.
	if err := s.Close(); err != nil {
		f.closeError = &ownerExitRequired{err}
		return f.closeError
	}
	return nil
}
