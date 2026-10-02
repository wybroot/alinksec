//go:build !linux

package guard

import "fmt"

func loginBlockPlatform(loginBlock, bool) error { return fmt.Errorf("SSH 来源封禁仅支持 Linux") }
func ClearLoginFirewall() error                 { return nil }
