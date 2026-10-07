//go:build windows

package baseline

func checkAuditdConfig(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "auditd_config 当前仅支持 Linux auditd 3.1.2 磁盘配置"}
}
