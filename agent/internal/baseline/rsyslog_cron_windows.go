//go:build windows

package baseline

func checkRsyslogCron(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "rsyslog_cron_routing 仅支持已验证的 Ubuntu24 rsyslog 磁盘配置"}
}
