//go:build windows

package baseline

func checkIPv4Host(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "linux_ipv4_host仅支持Linux当前网络命名空间"}
}
