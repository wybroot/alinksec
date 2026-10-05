//go:build windows

package baseline

func checkLocalIdentity(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "本地 Linux 身份文件检查不支持 Windows"}
}
