//go:build windows

package baseline

func checkSSHNotice(*CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "sshd_notice仅支持Ubuntu24 OpenSSH磁盘声明"}
}
