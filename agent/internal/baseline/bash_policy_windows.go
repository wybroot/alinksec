//go:build windows

package baseline

func checkBashGlobalPolicy(*CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "Bash全局启动声明仅支持Linux Ubuntu24"}
}
