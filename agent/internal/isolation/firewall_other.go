//go:build !linux && !windows

package isolation

import "fmt"

const helperName = "watchdog"

type nativeFirewall struct{}

func newFirewall() firewall               { return nativeFirewall{} }
func prepareBackends() ([]string, error)  { return nil, fmt.Errorf("unsupported isolation firewall") }
func validateBackends([]string) error     { return fmt.Errorf("unsupported isolation firewall") }
func (nativeFirewall) apply(*Lease) error { return fmt.Errorf("unsupported isolation firewall") }
func (nativeFirewall) clear(*Lease) error { return fmt.Errorf("unsupported isolation firewall") }
