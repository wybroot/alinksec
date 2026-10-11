//go:build windows

package baseline

func checkLogMetadata(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "linux_log_metadata 仅支持 Linux 固定日志路径"}
}
