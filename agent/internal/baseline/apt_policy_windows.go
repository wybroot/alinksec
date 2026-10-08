//go:build windows

package baseline

func checkAPTPolicy(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "apt_install_policy 仅支持已验证的 Ubuntu24 APT 磁盘配置"}
}
