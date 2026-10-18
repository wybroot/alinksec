//go:build !windows || !amd64

package filetrace

import "fmt"

type unsupported struct{}

func newNative(*Monitor, string) native { return unsupported{} }
func (unsupported) start() error        { return fmt.Errorf("native capture requires Windows amd64") }
func (unsupported) check() error        { return fmt.Errorf("native capture requires Windows amd64") }
func (unsupported) close() error        { return nil }
func Terminate(Identity) error          { return fmt.Errorf("native termination requires Windows amd64") }
