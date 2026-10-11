//go:build !linux

package baseline

func checkPAMSecureTTY(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "securetty当前仅支持Linux Ubuntu24"}
}
