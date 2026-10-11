//go:build windows

package baseline

func checkSudoers(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "sudoers_policy 仅支持已验证的 Ubuntu24 sudo 磁盘策略"}
}
