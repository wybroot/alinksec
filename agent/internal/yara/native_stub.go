//go:build !nativeyara || !cgo || (!linux && !windows)

package yara

func nativeVersion() string { return "" }
func nativeScan(rules, data []byte, probe bool, seconds int) ([]Match, string) {
	return nil, "yara_not_built"
}
