//go:build !windows

package windowslogin

func platformContract() uint32 { return 0 }
func newReader() Reader        { return nil }
func newFirewall() Firewall    { return nil }
