package baseline

func checkLinuxAudit(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "linux_audit 当前仅支持 Linux 内核审计"}
}
