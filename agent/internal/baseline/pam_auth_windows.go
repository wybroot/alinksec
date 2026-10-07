//go:build windows

package baseline

func checkPAMAuth(*CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "PAM 登录认证链检查仅支持 Linux login 服务"}
}
