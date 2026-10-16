//go:build !linux && !windows

package configguard

import (
	"fmt"
	"os"
)

func isLink(i os.FileInfo) bool { return i.Mode()&os.ModeSymlink != 0 }
func openNoFollow(string) (*os.File, error) {
	return nil, fmt.Errorf("configuration protection unsupported")
}
func privateFile(string) error    { return fmt.Errorf("configuration protection unsupported") }
func protectFile(string) error    { return fmt.Errorf("configuration protection unsupported") }
func writableParent(string) error { return fmt.Errorf("configuration protection unsupported") }
