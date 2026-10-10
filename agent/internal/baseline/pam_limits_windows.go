//go:build windows

package baseline

func checkPAMLimits(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "pam_limits 当前仅支持 Ubuntu24 Linux-PAM 1.5.3"}
}
