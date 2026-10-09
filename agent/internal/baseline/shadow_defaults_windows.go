//go:build windows

package baseline

func checkShadowAccountDefaults(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "Shadow新账户默认声明仅支持Linux Ubuntu24"}
}
