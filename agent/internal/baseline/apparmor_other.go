//go:build !linux

package baseline

func checkAppArmor(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Actual: appArmorPrefix(), Message: "AppArmor运行候选仅支持Linux"}
}
