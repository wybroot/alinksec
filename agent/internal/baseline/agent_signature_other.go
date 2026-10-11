//go:build !linux

package baseline

func checkAgentSignature(cs *CheckSpec, rt *AgentRuntime) ItemResult {
	return ItemResult{Error: true, Actual: agentSignaturePrefix, Message: "特征库一致性检查当前仅支持Linux"}
}
