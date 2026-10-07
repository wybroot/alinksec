//go:build windows

package baseline

func checkCronMetadata(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "debian_cron_metadata 仅支持已验证的 Ubuntu24 Debian cron 系统任务文件"}
}
