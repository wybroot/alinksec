package comm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"google.golang.org/protobuf/proto"
)

func cloneCmdWithIssuedAt(cmd *pb.Command, issuedAt int64) *pb.Command {
	clone := proto.Clone(cmd).(*pb.Command)
	clone.IssuedAt = issuedAt
	return clone
}

func quietCommLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func persistentTestClient(t *testing.T, workDir string) *Client {
	t.Helper()
	c, err := New(&config.Config{HeartbeatInterval: time.Hour, CollectInterval: time.Hour, DrainRatePerSec: 1000}, workDir, quietCommLogger())
	if err != nil {
		t.Fatalf("New(%s): %v", workDir, err)
	}
	c.state.AgentID = "test-agent-bkl025"
	return c
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestClassifyCommandCoversAll14CommandTypes(t *testing.T) {
	cases := []struct {
		name      string
		cmd       *pb.Command
		kind      string
		destr     bool
		dedicated bool
	}{
		{"baseline_check", &pb.Command{Payload: &pb.Command_BaselineCheck{BaselineCheck: &pb.CmdBaselineCheck{}}}, "baseline_check", false, false},
		{"vuln_scan", &pb.Command{Payload: &pb.Command_VulnScan{VulnScan: &pb.CmdVulnScan{}}}, "vuln_scan", false, false},
		{"policy_sync", &pb.Command{Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{}}}, "policy_sync", false, false},
		{"protect_isolate", &pb.Command{Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_ISOLATE_HOST}}}, "protect_isolate_host", true, true},
		{"protect_restore", &pb.Command{Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_RESTORE_ISOLATION}}}, "protect_restore_isolation", true, true},
		{"protect_kill", &pb.Command{Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS}}}, "protect_kill_process", true, false},
		{"agent_upgrade", &pb.Command{Payload: &pb.Command_AgentUpgrade{AgentUpgrade: &pb.CmdAgentUpgrade{}}}, "agent_upgrade", true, true},
		{"collect_now", &pb.Command{Payload: &pb.Command_CollectNow{CollectNow: &pb.CmdCollectNow{}}}, "collect_now", false, false},
		{"control_restart", &pb.Command{Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_RESTART}}}, "agent_control_restart", true, false},
		{"control_uninstall", &pb.Command{Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_ARM_UNINSTALL}}}, "agent_control_arm_uninstall", true, false},
		{"control_pause", &pb.Command{Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_PAUSE_COLLECT}}}, "agent_control_pause_collect", false, false},
		{"control_resume", &pb.Command{Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_RESUME_COLLECT}}}, "agent_control_resume_collect", false, false},
		{"virus_scan", &pb.Command{Payload: &pb.Command_VirusScan{VirusScan: &pb.CmdVirusScan{}}}, "virus_scan", true, false},
		{"virus_action", &pb.Command{Payload: &pb.Command_VirusAction{VirusAction: &pb.CmdVirusAction{}}}, "virus_action", true, false},
		{"signature_update", &pb.Command{Payload: &pb.Command_SignatureUpdate{SignatureUpdate: &pb.CmdSignatureUpdate{}}}, "signature_update", true, false},
		{"vuln_fix", &pb.Command{Payload: &pb.Command_VulnFix{VulnFix: &pb.CmdVulnFix{}}}, "vuln_fix", true, false},
		{"windows_update_scan", &pb.Command{Payload: &pb.Command_WindowsUpdateScan{WindowsUpdateScan: &pb.CmdWindowsUpdateScan{}}}, "windows_update_scan", false, false},
		{"scap_scan", &pb.Command{Payload: &pb.Command_ScapScan{ScapScan: &pb.CmdScapScan{}}}, "scap_scan", false, true},
		{"evidence_collect", &pb.Command{Payload: &pb.Command_EvidenceCollect{EvidenceCollect: &pb.CmdEvidenceCollect{}}}, "evidence_collect", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyCommand(tc.cmd)
			if got.kind != tc.kind || got.destructive != tc.destr || got.hasDedicatedLedger != tc.dedicated {
				t.Fatalf("classifyCommand(%s) = %+v, want kind=%s destr=%v dedicated=%v", tc.name, got, tc.kind, tc.destr, tc.dedicated)
			}
		})
	}

	if got := classifyCommand(nil); got.kind != "unknown" || got.destructive {
		t.Fatalf("unexpected nil classification: %+v", got)
	}
}

func TestPersistentDedupSurvivesRestartAndLostAckWithoutReexecutingDestructiveActions(t *testing.T) {
	t.Run("kill_process_never_reexecutes_after_restart_or_failed_ack", func(t *testing.T) {
		oldKill := killProcessByPID
		t.Cleanup(func() { killProcessByPID = oldKill })

		var calls atomic.Int32
		killProcessByPID = func(pid int32) bool {
			calls.Add(1)
			return pid == 4242
		}

		workDir := t.TempDir()
		c1 := persistentTestClient(t, workDir)
		cmd := &pb.Command{
			CmdId:    "cmd-kill-4242",
			IssuedAt: 1000,
			Payload: &pb.Command_ProtectAction{
				ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "4242"},
			},
		}
		acks := c1.handleCommand(cmd, nil, context.Background())
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_DONE || calls.Load() != 1 {
			t.Fatalf("initial kill failed: acks=%+v calls=%d", acks, calls.Load())
		}

		// Simulate ACK lost in transit and process restart, plus server updating IssuedAt on resend.
		c2 := persistentTestClient(t, workDir)
		replayed := cloneCmdWithIssuedAt(cmd, 9999)
		acks2 := c2.handleCommand(replayed, nil, context.Background())
		if len(acks2) != 1 || acks2[0].Stage != pb.RptAck_DONE || acks2[0].Message != acks[1].Message || calls.Load() != 1 {
			t.Fatalf("replay re-executed or lost ACK: acks=%+v calls=%d", acks2, calls.Load())
		}

		// Verify failure ACK also carries non-zero Code and is retained across restart.
		failCmd := &pb.Command{
			CmdId: "cmd-kill-missing",
			Payload: &pb.Command_ProtectAction{
				ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "9999"},
			},
		}
		failAcks := c2.handleCommand(failCmd, nil, context.Background())
		if len(failAcks) != 2 || failAcks[1].Stage != pb.RptAck_FAILED || failAcks[1].Code != 1 || calls.Load() != 2 {
			t.Fatalf("failed kill unexpected: %+v calls=%d", failAcks, calls.Load())
		}
		c3 := persistentTestClient(t, workDir)
		failReplay := c3.handleCommand(failCmd, nil, context.Background())
		if len(failReplay) != 1 || failReplay[0].Stage != pb.RptAck_FAILED || failReplay[0].Code != 1 || calls.Load() != 2 {
			t.Fatalf("failed kill re-executed: %+v calls=%d", failReplay, calls.Load())
		}
	})

	t.Run("restart_persists_before_exit_and_ignores_resend_loop", func(t *testing.T) {
		oldExit, oldDelay := exitProcess, restartExitDelay
		t.Cleanup(func() { exitProcess = oldExit; restartExitDelay = oldDelay })

		var exits atomic.Int32
		exitProcess = func(int) { exits.Add(1) }
		restartExitDelay = 5 * time.Millisecond

		workDir := t.TempDir()
		c1 := persistentTestClient(t, workDir)
		cmd := &pb.Command{
			CmdId:   "cmd-restart-1",
			Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_RESTART}},
		}
		acks := c1.handleCommand(cmd, nil, context.Background())
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_DONE || acks[1].Message != "restarting" {
			t.Fatalf("initial restart unexpected: %+v", acks)
		}
		waitForCondition(t, 2*time.Second, func() bool { return exits.Load() == 1 }, "restart exit hook not triggered")

		c2 := persistentTestClient(t, workDir)
		replayed := c2.handleCommand(cmd, nil, context.Background())
		time.Sleep(30 * time.Millisecond)
		if len(replayed) != 1 || replayed[0].Stage != pb.RptAck_DONE || replayed[0].Message != "restarting" || exits.Load() != 1 {
			t.Fatalf("replayed restart caused exit loop: acks=%+v exits=%d", replayed, exits.Load())
		}
	})

	t.Run("arm_uninstall_not_rearmed_after_restart", func(t *testing.T) {
		workDir := t.TempDir()
		c1 := persistentTestClient(t, workDir)
		cmd := &pb.Command{
			CmdId: "cmd-arm-1",
			Payload: &pb.Command_AgentControl{
				AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_ARM_UNINSTALL, UninstallToken: "tok-secret-1234"},
			},
		}
		acks := c1.handleCommand(cmd, nil, context.Background())
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_DONE || c1.state.UninstallToken != "tok-secret-1234" {
			t.Fatalf("arm uninstall failed: acks=%+v token=%q", acks, c1.state.UninstallToken)
		}
		// Simulate one-time token consumption before server retries lost ACK.
		c1.state.UninstallToken = ""
		c1.state.UninstallExpire = 0
		if err := c1.state.Save(workDir); err != nil {
			t.Fatal(err)
		}

		c2 := persistentTestClient(t, workDir)
		replayed := c2.handleCommand(cmd, nil, context.Background())
		if len(replayed) != 1 || replayed[0].Stage != pb.RptAck_DONE || c2.state.UninstallToken != "" {
			t.Fatalf("replayed arm_uninstall re-armed token: acks=%+v token=%q", replayed, c2.state.UninstallToken)
		}
	})

	t.Run("vuln_fix_async_terminal_persisted_across_restart", func(t *testing.T) {
		oldFix := runVulnFix
		t.Cleanup(func() { runVulnFix = oldFix })

		var calls atomic.Int32
		runVulnFix = func(taskID string, _ []*pb.FixItem, _ string, _ *slog.Logger) *pb.RptFixResult {
			calls.Add(1)
			return &pb.RptFixResult{TaskId: taskID, Results: []*pb.FixResultItem{{RefId: "CVE-2026-0001", Success: true}}}
		}

		workDir := t.TempDir()
		c1 := persistentTestClient(t, workDir)
		cmd := &pb.Command{
			CmdId: "cmd-fix-1",
			Payload: &pb.Command_VulnFix{
				VulnFix: &pb.CmdVulnFix{TaskId: "task-fix-1", Fixes: []*pb.FixItem{{RefId: "CVE-2026-0001"}}},
			},
		}
		acks := c1.handleCommand(cmd, nil, context.Background())
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_RUNNING {
			t.Fatalf("expected running ack: %+v", acks)
		}
		waitForCondition(t, 2*time.Second, func() bool {
			got := c1.dedup.Get("cmd-fix-1")
			return got != nil && got.Stage == pb.RptAck_DONE
		}, "vuln_fix terminal ACK never committed")

		c2 := persistentTestClient(t, workDir)
		replayed := c2.handleCommand(cmd, nil, context.Background())
		if len(replayed) != 1 || replayed[0].Stage != pb.RptAck_DONE || calls.Load() != 1 {
			t.Fatalf("replayed vuln_fix re-executed: acks=%+v calls=%d", replayed, calls.Load())
		}
	})

	t.Run("policy_sync_replays_persisted_ack", func(t *testing.T) {
		workDir := t.TempDir()
		c1 := persistentTestClient(t, workDir)
		cmd := &pb.Command{
			CmdId:   "cmd-policy-v2",
			Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{PolicyVersion: "v2"}},
		}
		acks := c1.handleCommand(cmd, nil, context.Background())
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_DONE {
			t.Fatalf("policy sync failed: %+v", acks)
		}

		c2 := persistentTestClient(t, workDir)
		c2.state.PolicyVersion = "v1-should-not-change"
		replayed := c2.handleCommand(cmd, nil, context.Background())
		if len(replayed) != 1 || replayed[0].Stage != pb.RptAck_DONE || c2.state.PolicyVersion != "v1-should-not-change" {
			t.Fatalf("replayed policy sync re-executed: acks=%+v version=%q", replayed, c2.state.PolicyVersion)
		}
	})
}

func TestPersistentDedupRefusesDestructiveReplayAfterCrashInterruption(t *testing.T) {
	oldKill := killProcessByPID
	t.Cleanup(func() { killProcessByPID = oldKill })

	var killCalls atomic.Int32
	killProcessByPID = func(int32) bool { killCalls.Add(1); return true }

	workDir := t.TempDir()
	store1, err := newPersistentCmdDedup(workDir, 10, 10)
	if err != nil {
		t.Fatal(err)
	}

	killCmd := &pb.Command{
		CmdId:   "cmd-crashed-kill",
		Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "123"}},
	}
	killDigest, _ := commandDigest(killCmd)
	if prev, err := store1.CheckOrBegin(killCmd.CmdId, classifyCommand(killCmd), killDigest); err != nil || prev != nil {
		t.Fatalf("expected clean intent write: prev=%v err=%v", prev, err)
	}

	fixCmd := &pb.Command{
		CmdId:   "cmd-crashed-fix",
		Payload: &pb.Command_VulnFix{VulnFix: &pb.CmdVulnFix{TaskId: "t1"}},
	}
	fixDigest, _ := commandDigest(fixCmd)
	if prev, err := store1.CheckOrBegin(fixCmd.CmdId, classifyCommand(fixCmd), fixDigest); err != nil || prev != nil {
		t.Fatalf("expected clean intent write for vuln_fix: prev=%v err=%v", prev, err)
	}

	// Simulate crash before DONE/FAILED was written; check persisted RUNNING intent directly via handleCommand after restart.
	c2 := persistentTestClient(t, workDir)
	acks := c2.handleCommand(killCmd, nil, context.Background())
	if len(acks) != 1 || acks[0].Stage != pb.RptAck_FAILED || !strings.Contains(acks[0].Message, "interrupted") || killCalls.Load() != 0 {
		t.Fatalf("crashed destructive command was re-executed: acks=%+v kills=%d", acks, killCalls.Load())
	}

	// Third restart/replay stays failed cleanly.
	c3 := persistentTestClient(t, workDir)
	acksAgain := c3.handleCommand(killCmd, nil, context.Background())
	if len(acksAgain) != 1 || acksAgain[0].Stage != pb.RptAck_FAILED || acksAgain[0].Message != acks[0].Message || killCalls.Load() != 0 {
		t.Fatalf("subsequent replay drifted: %+v kills=%d", acksAgain, killCalls.Load())
	}

	// Non-destructive command interrupted before completion across restart may safely run again.
	collectCmd := &pb.Command{CmdId: "cmd-interrupted-collect", Payload: &pb.Command_CollectNow{CollectNow: &pb.CmdCollectNow{}}}
	collectDigest, _ := commandDigest(collectCmd)
	if err := c3.dedup.PutDurable(collectCmd.CmdId, &pb.RptAck{CmdId: collectCmd.CmdId, Stage: pb.RptAck_RUNNING}); err != nil {
		t.Fatal(err)
	}
	storeReopened, err := newPersistentCmdDedup(workDir, defaultGeneralDedupCap, defaultProtectedDedupCap)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := storeReopened.CheckOrBegin(collectCmd.CmdId, classifyCommand(collectCmd), collectDigest)
	if err != nil || prev != nil {
		t.Fatalf("non-destructive command should be allowed to retry after crash: prev=%+v err=%v", prev, err)
	}
}

func TestDestructiveRecordsSurviveGeneralLRUEvictionAndFailClosedWhenSaturated(t *testing.T) {
	workDir := t.TempDir()
	now := time.Unix(1700000000, 0)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	store, err := newPersistentCmdDedup(workDir, 5, 2)
	if err != nil {
		t.Fatal(err)
	}
	store.now = clock

	// Commit one destructive command and another destructive command.
	d1 := &pb.Command{CmdId: "destr-1", Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_RESTART}}}
	dig1, _ := commandDigest(d1)
	if prev, err := store.CheckOrBegin(d1.CmdId, classifyCommand(d1), dig1); err != nil || prev != nil {
		t.Fatal(prev, err)
	}
	if err := store.PutDurable(d1.CmdId, &pb.RptAck{CmdId: d1.CmdId, Stage: pb.RptAck_DONE, Message: "restarting"}); err != nil {
		t.Fatal(err)
	}

	// Flood 20 non-destructive commands (4x generalCap=5). Destructive destr-1 must survive.
	for i := 0; i < 20; i++ {
		id := "general-" + string(rune('a'+i))
		cmd := &pb.Command{CmdId: id, Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{PolicyVersion: "v1"}}}
		dig, _ := commandDigest(cmd)
		if prev, err := store.CheckOrBegin(id, classifyCommand(cmd), dig); err != nil || prev != nil {
			t.Fatalf("general command %s failed: prev=%v err=%v", id, prev, err)
		}
		if err := store.PutDurable(id, &pb.RptAck{CmdId: id, Stage: pb.RptAck_DONE, Message: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if store.Get("general-a") != nil {
		t.Fatal("oldest general command should have been evicted by LRU")
	}
	if got := store.Get(d1.CmdId); got == nil || got.Stage != pb.RptAck_DONE {
		t.Fatalf("general flood evicted protected destructive entry: %+v", got)
	}

	// Fill protectedCap=2 with a second destructive command.
	d2 := &pb.Command{CmdId: "destr-2", Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "1"}}}
	dig2, _ := commandDigest(d2)
	if prev, err := store.CheckOrBegin(d2.CmdId, classifyCommand(d2), dig2); err != nil || prev != nil {
		t.Fatal(prev, err)
	}
	if err := store.PutDurable(d2.CmdId, &pb.RptAck{CmdId: d2.CmdId, Stage: pb.RptAck_DONE}); err != nil {
		t.Fatal(err)
	}

	// Reopen across restart and verify destr-1 & destr-2 survived while protectedCap=2 blocks a 3rd fresh command before retention expires.
	store2, err := newPersistentCmdDedup(workDir, 5, 2)
	if err != nil {
		t.Fatal(err)
	}
	store2.now = clock
	if got := store2.Get(d1.CmdId); got == nil || got.Stage != pb.RptAck_DONE {
		t.Fatalf("reloaded store missing destructive record: %+v", got)
	}

	advance(23 * time.Hour)
	d3 := &pb.Command{CmdId: "destr-3", Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "2"}}}
	dig3, _ := commandDigest(d3)
	if _, err := store2.CheckOrBegin(d3.CmdId, classifyCommand(d3), dig3); !errors.Is(err, errDedupCapacityExhausted) {
		t.Fatalf("expected fail-closed capacity error before 24h retention, got %v", err)
	}

	// Wire through Client to verify exact FAILED ACK message on saturation.
	oldKill := killProcessByPID
	t.Cleanup(func() { killProcessByPID = oldKill })
	var killCalls atomic.Int32
	killProcessByPID = func(int32) bool { killCalls.Add(1); return true }
	client := &Client{workDir: workDir, state: &State{AgentID: "a"}, dedup: store2, log: quietCommLogger()}
	acks := client.handleCommand(d3, nil, context.Background())
	if len(acks) != 1 || acks[0].Stage != pb.RptAck_FAILED || acks[0].Message != "command_dedup_capacity_exhausted" || killCalls.Load() != 0 {
		t.Fatalf("saturated protected bucket failed open: acks=%+v kills=%d", acks, killCalls.Load())
	}

	// After 24h passes, oldest terminal entry may be evicted for d3.
	advance(2 * time.Hour)
	acks = client.handleCommand(d3, nil, context.Background())
	if len(acks) != 2 || acks[1].Stage != pb.RptAck_DONE || killCalls.Load() != 1 {
		t.Fatalf("expired destructive entry should allow d3: acks=%+v kills=%d", acks, killCalls.Load())
	}
	// Get(d1) refreshed d1's LRU recency behind d2, so d2 is the oldest expired entry evicted.
	if store2.Get(d2.CmdId) != nil || store2.Get(d1.CmdId) == nil {
		t.Fatal("expected least-recently-used expired destructive entry d2 to be evicted while d1 remains")
	}
}

func TestPersistentDedupRejectsPayloadConflictCorruptJournalAndUnwritableIntent(t *testing.T) {
	t.Run("payload_conflict_rejected_while_issued_at_resend_allowed", func(t *testing.T) {
		oldKill := killProcessByPID
		t.Cleanup(func() { killProcessByPID = oldKill })
		var calls atomic.Int32
		killProcessByPID = func(int32) bool { calls.Add(1); return true }

		c := persistentTestClient(t, t.TempDir())
		orig := &pb.Command{
			CmdId:    "cmd-conflict",
			IssuedAt: 100,
			Payload:  &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "1001"}},
		}
		if acks := c.handleCommand(orig, nil, context.Background()); len(acks) != 2 || acks[1].Stage != pb.RptAck_DONE || calls.Load() != 1 {
			t.Fatalf("initial failed: %+v", acks)
		}

		// Updated IssuedAt with identical payload replays cleanly.
		if acks := c.handleCommand(cloneCmdWithIssuedAt(orig, 200), nil, context.Background()); len(acks) != 1 || acks[0].Stage != pb.RptAck_DONE || calls.Load() != 1 {
			t.Fatalf("issued_at resend failed: %+v", acks)
		}

		// Same CmdId with altered target must fail closed with conflict.
		forged := &pb.Command{
			CmdId:    "cmd-conflict",
			IssuedAt: 300,
			Payload:  &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "2002"}},
		}
		acks := c.handleCommand(forged, nil, context.Background())
		if len(acks) != 1 || acks[0].Stage != pb.RptAck_FAILED || acks[0].Message != "command_id_payload_conflict" || calls.Load() != 1 {
			t.Fatalf("payload conflict executed or not rejected: %+v calls=%d", acks, calls.Load())
		}
	})

	t.Run("corrupt_journal_fails_closed", func(t *testing.T) {
		badPayloads := map[string]string{
			"invalid_json":    "{not-json",
			"wrong_schema":    `{"schema":99,"general":[],"protected":[]}`,
			"invalid_stage":   `{"schema":1,"general":[{"id":"a","stage":99,"updated_at":10}],"protected":[]}`,
			"invalid_digest":  `{"schema":1,"general":[{"id":"a","digest":"xyz","stage":4,"updated_at":10}],"protected":[]}`,
			"wrong_bucket":    `{"schema":1,"general":[{"id":"a","destructive":true,"stage":4,"updated_at":10}],"protected":[]}`,
			"duplicate_id":    `{"schema":1,"general":[{"id":"a","stage":4,"updated_at":10}],"protected":[{"id":"a","destructive":true,"stage":4,"updated_at":10}]}`,
			"unknown_field":   `{"schema":1,"extra":1,"general":[],"protected":[]}`,
		}
		for name, raw := range badPayloads {
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "cmd-dedup.json"), []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := newPersistentCmdDedup(dir, 10, 10); err == nil {
					t.Fatalf("%s unexpectedly loaded corrupt journal", name)
				}
				if _, err := New(&config.Config{}, dir, quietCommLogger()); err == nil {
					t.Fatalf("%s unexpectedly allowed Client startup", name)
				}
			})
		}
	})

	t.Run("unwritable_intent_blocks_destructive_side_effect_and_restart", func(t *testing.T) {
		oldKill, oldExit := killProcessByPID, exitProcess
		t.Cleanup(func() { killProcessByPID = oldKill; exitProcess = oldExit })

		var killCalls, exitCalls atomic.Int32
		killProcessByPID = func(int32) bool { killCalls.Add(1); return true }
		exitProcess = func(int) { exitCalls.Add(1) }

		// Directory at cmd-dedup.json blocks atomic replace while leaving directory writable.
		workDir := t.TempDir()
		store, err := newPersistentCmdDedup(workDir, 10, 10)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(workDir, "cmd-dedup.json"), 0700); err != nil {
			t.Fatal(err)
		}
		client := &Client{workDir: workDir, state: &State{AgentID: "a"}, dedup: store, log: quietCommLogger()}

		killCmd := &pb.Command{
			CmdId:   "cmd-unwritable-kill",
			Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_KILL_PROCESS, Target: "1"}},
		}
		acks := client.handleCommand(killCmd, nil, context.Background())
		if len(acks) != 1 || acks[0].Stage != pb.RptAck_FAILED || acks[0].Message != "command_dedup_persistence_failed" || killCalls.Load() != 0 {
			t.Fatalf("unwritable intent did not block kill: acks=%+v kills=%d", acks, killCalls.Load())
		}

		restartCmd := &pb.Command{
			CmdId:   "cmd-unwritable-restart",
			Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_RESTART}},
		}
		rAcks := client.handleCommand(restartCmd, nil, context.Background())
		if len(rAcks) != 1 || rAcks[0].Stage != pb.RptAck_FAILED || exitCalls.Load() != 0 {
			t.Fatalf("unwritable intent allowed restart: acks=%+v exits=%d", rAcks, exitCalls.Load())
		}

		// Sanity-check valid persisted JSON schema on clean path.
		cleanDir := t.TempDir()
		c := persistentTestClient(t, cleanDir)
		_ = c.handleCommand(killCmd, nil, context.Background())
		data, err := os.ReadFile(filepath.Join(cleanDir, "cmd-dedup.json"))
		if err != nil {
			t.Fatal(err)
		}
		var j dedupJournal
		if err := json.Unmarshal(data, &j); err != nil || j.Schema != 1 || len(j.Protected) != 1 || j.Protected[0].ID != killCmd.CmdId {
			t.Fatalf("unexpected persisted journal: err=%v body=%s", err, string(data))
		}
	})
}
