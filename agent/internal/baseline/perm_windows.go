//go:build windows

package baseline

// checkFilePerm Windows：NTFS ACL 与 POSIX mode 不对应，当前模板未含 Windows 权限项，
// 命中即按“不支持”失败落库（不静默通过）。
func checkFilePerm(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Actual: cs.Target,
		Message: "file_perm 检查暂不支持 Windows（等保 Windows 模板将使用 ACL 检查）"}
}
