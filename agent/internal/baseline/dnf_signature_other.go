//go:build !linux

package baseline

func checkDNFSignature(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Actual: dnfSignaturePrefix, Message: "DNF签名声明当前仅支持Linux Rocky9"}
}
