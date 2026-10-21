//go:build !windows

package baseline

func checkWindowsSecurity(s *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "Windows security policy requires a Windows Agent"}
}
