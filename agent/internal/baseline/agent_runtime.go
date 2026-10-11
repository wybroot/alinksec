package baseline

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

const agentChannelReference = "self_process=running,current_mtls_session=active,successful_send_and_receive_age<=60s"
const agentSignatureReference = "manifest=nonempty_hash_only,cache=disk_exact,inputs=trusted_stable"
const agentChannelPrefix = "scope=current-agent-channel server_application_acceptance_state=unverified server_persistence_state=unverified other_agents_state=unverified protection_state=unverified snapshot_state=non_atomic "
const agentSignaturePrefix = "scope=current-agent-signature-cache-vs-disk source_authenticity_state=unverified freshness_state=unverified detection_coverage_state=unverified engine_instance_state=unverified package_digest_state=unverified snapshot_state=non_atomic "

// Runtime comes from the client executing this task, never from check JSON or
// global connection history. Cache observations do not reload signatures.
type AgentRuntime struct {
	WorkDir   string
	Channel   func(context.Context) (ChannelObservation, error)
	Signature func(context.Context) (SignatureObservation, error)
}
type ChannelObservation struct {
	Session               uint64
	Active                bool
	LastSend, LastReceive time.Time
}
type SignatureEntry struct {
	Name     string
	Severity int32
}
type SignatureObservation struct {
	Generation           uint64
	Version              string
	HashCount, RuleCount int
	Hashes               map[string]SignatureEntry
}

func checkAgentRuntime(cs *CheckSpec, rt *AgentRuntime) ItemResult {
	prefix := agentChannelPrefix
	if cs.Option == "hash_inventory" {
		prefix = agentSignaturePrefix
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || rt == nil {
		return ItemResult{Error: true, Actual: prefix, Message: "当前Agent运行上下文或Linux平台无法确认"}
	}
	if cs.Option == "hash_inventory" {
		return checkAgentSignature(cs, rt)
	}
	if rt.Channel == nil {
		return ItemResult{Error: true, Actual: prefix, Message: "当前Agent通道观测不可用"}
	}
	return observeAgentChannel(cs, rt.Channel, time.Now)
}

func observeAgentChannel(cs *CheckSpec, query func(context.Context) (ChannelObservation, error), clock func() time.Time) ItemResult {
	failed := func() ItemResult {
		return ItemResult{Error: true, Actual: agentChannelPrefix, Message: "当前会话变化、时间戳未知或超过共同读取预算"}
	}
	start := clock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	a, err := query(ctx)
	if err != nil {
		return failed()
	}
	b, err := query(ctx)
	if err != nil || ctx.Err() != nil {
		return failed()
	}
	now := clock()
	if now.Before(start) || now.Sub(start) > time.Duration(cs.TimeoutMs)*time.Millisecond || a.Session != b.Session || a.Active != b.Active || b.LastSend.Before(a.LastSend) || b.LastReceive.Before(a.LastReceive) {
		return failed()
	}
	if b.Active && b.Session == 0 {
		return failed()
	}
	ages := [2]string{"not_observed", "not_observed"}
	recent := true
	for i, stamp := range []time.Time{b.LastSend, b.LastReceive} {
		if stamp.IsZero() {
			recent = false
			continue
		}
		if stamp.After(now) {
			return failed()
		}
		age := now.Sub(stamp)
		ages[i] = fmt.Sprintf("%d", age.Milliseconds())
		recent = recent && age <= 60*time.Second
	}
	passed := b.Active && recent
	r := ItemResult{Passed: passed, Actual: fmt.Sprintf("%sself_process=running current_session_active=%t send_age_ms=%s receive_age_ms=%s", agentChannelPrefix, b.Active, ages[0], ages[1])}
	if !passed {
		r.Message = "当前mTLS会话或最近60秒成功收发不满足参考"
	}
	return r
}
