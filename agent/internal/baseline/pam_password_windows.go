//go:build windows

package baseline

func checkPAMPassword(*CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "PAM 口令检查仅支持 Linux passwd 服务"}
}
