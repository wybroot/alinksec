package comm

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/alinksec/alinksec-agent/internal/baseline"
	"github.com/alinksec/alinksec-agent/internal/collector"
	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/fixer"
	"github.com/alinksec/alinksec-agent/internal/guard"
	"github.com/alinksec/alinksec-agent/internal/identity"
	"github.com/alinksec/alinksec-agent/internal/logcollect"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/scan"
	"github.com/alinksec/alinksec-agent/internal/sysmetrics"
	"github.com/alinksec/alinksec-agent/internal/upgrade"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
)

// Client Agent 通信客户端：注册 + 主通道双向流
type Client struct {
	cfg     *config.Config
	workDir string
	state   *State
	queue   *OfflineQueue
	dedup   *cmdDedup
	log     *slog.Logger

	// 资产采集：collectTrigger 收集采集请求（空切片 = 全部），
	// pendingReports 承接在线采集产物；断线期间业务上报直接落盘。
	collectTrigger chan []string
	pendingReports chan *pb.Report
	lastCollectAt  time.Time
	reportMu       sync.Mutex
	channelActive  bool

	// 基线核查单飞：同一时刻仅允许一个核查任务执行（串行执行避免检测命令并发放大负载）
	baselineBusy atomic.Bool
	// 采集暂停标志：CmdAgentControl.PAUSE/RESUME 切换（资源冲突时让路，防护不暂停）
	collectPaused atomic.Bool
	// 安全扫描单飞：弱口令字典比对 CPU 密集，拒绝并发扫描
	scanBusy atomic.Bool
	// 病毒扫描单飞：全盘遍历 IO 密集，拒绝并发扫描
	virusBusy atomic.Bool
	// 特征库更新单飞：下载安装互斥（避免并发替换 db 目录）
	sigBusy atomic.Bool
	// 配置修复单飞：文件写入互斥（避免并发改同一配置文件）
	fixBusy atomic.Bool

	// 勒索诱饵防护引擎（本地响应，事件经 reportSecurityEvent 上报）
	grd *guard.Guard
}

// New 创建通信客户端（加载本地状态与离线队列）
func New(cfg *config.Config, workDir string, log *slog.Logger) (*Client, error) {
	st, err := LoadState(workDir)
	if err != nil {
		return nil, fmt.Errorf("加载本地状态: %w", err)
	}
	q, err := NewOfflineQueue(workDir)
	if err != nil {
		return nil, fmt.Errorf("初始化离线队列: %w", err)
	}
	c := &Client{
		cfg:            cfg,
		workDir:        workDir,
		state:          st,
		queue:          q,
		dedup:          newCmdDedup(1000),
		log:            log,
		collectTrigger: make(chan []string, 2),
		pendingReports: make(chan *pb.Report, 4),
	}
	// 平台热下发策略优先于本地 agent.yml（重启后仍生效，直至下次同步覆盖）
	c.loadPersistedPolicy(cfg)
	c.grd = guard.New(&cfg.Decoy, cfg.ProcessRules, workDir, log, c.reportSecurityEvent)
	c.grd.SetServerAddr(cfg.ServerAddr)
	c.grd.UpdateProtection(cfg.FileRules, cfg.LoginRules)
	// 病毒实时防护（docs/05 §1.5）：常驻 L1 引擎注入 guard，窗口 diff 文件准实时检查
	vEngine := virusscan.NewEngine(workDir, log)
	c.grd.SetVirusEngine(func(path string) *pb.VirusFinding {
		return vEngine.CheckAndQuarantine(path, workDir)
	})
	return c, nil
}

// loadPersistedPolicy 读工作目录 policy.json（最近一次 PolicySync 全量快照）覆盖 decoy 配置段
func (c *Client) loadPersistedPolicy(cfg *config.Config) {
	b, err := os.ReadFile(filepath.Join(c.workDir, "policy.json"))
	if err != nil {
		return
	}
	c.applyPolicyJson(string(b), false)
}

// applyPolicyJson applies a complete policy snapshot. It validates and persists
// the snapshot before changing the running configuration, so a failed sync does
// not replace the last known-good local policy.
func (c *Client) applyPolicyJson(js string, hot bool) error {
	var p struct {
		Decoy        *config.DecoyConfig   `json:"decoy"`
		ProcessRules *[]config.ProcessRule `json:"process_rules"`
		FileRules    *[]config.FileRule    `json:"file_rules"`
		LoginRules   *[]config.LoginRule   `json:"login_rules"`
	}
	if err := json.Unmarshal([]byte(js), &p); err != nil {
		return fmt.Errorf("解析 policy_json: %w", err)
	}
	files, logins := c.cfg.FileRules, c.cfg.LoginRules
	if p.FileRules != nil {
		files = *p.FileRules
	}
	if p.LoginRules != nil {
		logins = *p.LoginRules
	}
	if err := config.ValidateProtection(files, logins); err != nil {
		return err
	}
	if hot { // 快照落盘，重启后仍生效直至下次同步
		path := filepath.Join(c.workDir, "policy.json")
		if err := os.WriteFile(path+".tmp", []byte(js), 0600); err != nil {
			return fmt.Errorf("持久化 policy_json: %w", err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return fmt.Errorf("替换 policy_json: %w", err)
		}
	}
	if p.Decoy != nil {
		c.cfg.Decoy = *p.Decoy
		c.cfg.Decoy.Normalize()
	}
	c.cfg.FileRules, c.cfg.LoginRules = files, logins
	if c.grd != nil {
		c.grd.UpdateProtection(files, logins)
	}
	if p.ProcessRules != nil {
		c.cfg.ProcessRules = append([]config.ProcessRule(nil), (*p.ProcessRules)...)
	}
	if hot && c.grd != nil {
		d := c.cfg.Decoy
		c.grd.UpdatePolicy(&d, c.cfg.ProcessRules)
	}
	return nil
}

// AgentID 返回注册身份（未注册为空）
func (c *Client) AgentID() string { return c.state.AgentID }

/* ==================== 注册 ==================== */

// EnsureEnrolled 未注册时执行 Enroll（首次信任由一次性 token 保证，协议设计 §6）
func (c *Client) EnsureEnrolled(ctx context.Context) error {
	if CertsExist(c.workDir) && c.state.AgentID != "" {
		return nil
	}
	if c.cfg.EnrollToken == "" {
		return errors.New("未注册且配置缺少 enroll_token")
	}
	if c.cfg.EnrollCAFile == "" {
		return errors.New("首次注册必须配置 enroll_ca_file")
	}
	caPEM, err := os.ReadFile(c.cfg.EnrollCAFile)
	if err != nil {
		return fmt.Errorf("读取注册 CA 文件: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("注册 CA 文件不包含有效 PEM 证书")
	}
	serverName := c.cfg.ServerNameOverride
	if serverName == "" {
		serverName, _, err = net.SplitHostPort(c.cfg.ServerAddr)
		if err != nil {
			return fmt.Errorf("解析服务端地址: %w", err)
		}
	}
	conn, err := grpc.NewClient(c.cfg.ServerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12,
		})))
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := pb.NewEnrollServiceClient(conn).Enroll(ctx, &pb.EnrollRequest{
		EnrollToken: c.cfg.EnrollToken,
		Host:        identity.HostInfo(),
		Nonce:       identity.Nonce(),
	})
	if err != nil {
		return fmt.Errorf("Enroll RPC: %w", err)
	}
	if err := saveCerts(c.workDir, resp.GetClientCert(), resp.GetClientKey(), []byte(resp.GetCaCert())); err != nil {
		return fmt.Errorf("持久化证书: %w", err)
	}
	c.state.AgentID = resp.GetAgentId()
	if err := c.state.Save(c.workDir); err != nil {
		return err
	}
	c.log.Info("注册成功", "agent_id", c.state.AgentID)
	return nil
}

/* ==================== 主通道 ==================== */

// Run 主循环：建流 → 收发 → 断线指数退避重连（协议设计 §5）
func (c *Client) Run(ctx context.Context) error {
	if c.grd != nil {
		go c.grd.Run(ctx)
	}
	go c.collectLoop(ctx)
	go c.metricsLoop(ctx)
	go c.logLoop(ctx)
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.runChannelOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.log.Warn("主通道断开，退避重连", "err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitter(backoff)):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// runChannelOnce 建立一次双向流会话，返回错误即触发重连
func (c *Client) runChannelOnce(ctx context.Context) error {
	tlsCfg, err := c.mtlsConfig()
	if err != nil {
		return fmt.Errorf("加载 mTLS 材料: %w", err)
	}
	conn, err := grpc.NewClient(c.cfg.ServerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer conn.Close()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := pb.NewAgentChannelClient(conn).Channel(sctx)
	if err != nil {
		return fmt.Errorf("建立 Channel 流: %w", err)
	}
	c.setChannelActive(true)
	defer c.setChannelActive(false)

	sendCh := make(chan *pb.Report, 256)
	sendErr := make(chan error, 1)
	go func() {
		defer close(sendCh)
		// 发送协程：唯一写 stream 的地方
		sendErr <- c.sendLoop(sctx, stream, sendCh)
	}()

	c.log.Info("主通道已建立", "agent_id", c.state.AgentID)

	// 重连成功立即心跳（协议设计 §5）
	sendCh <- c.buildHeartbeat()

	// 连接建立后触发一次资产采集（受最小间隔约束，防止连接抖动重复采集）
	c.triggerCollect(nil)

	// 接收协程在当前 goroutine：处理下行指令
	recvErr := make(chan error, 1)
	go func() {
		for {
			cmd, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if acks := c.handleCommand(cmd, sendCh, sctx); len(acks) > 0 {
				for _, a := range acks {
					select {
					case sendCh <- c.wrapAck(a):
					case <-sctx.Done():
						return
					}
				}
			}
		}
	}()

	select {
	case err := <-recvErr:
		cancel()
		<-sendErr
		return fmt.Errorf("接收中断: %w", err)
	case err := <-sendErr:
		cancel()
		return fmt.Errorf("发送中断: %w", err)
	case <-ctx.Done():
		cancel()
		<-sendErr
		return ctx.Err()
	}
}

// sendLoop 发送协程：心跳定时、离线队列补传、sendCh 消费
func (c *Client) sendLoop(ctx context.Context, stream pb.AgentChannel_ChannelClient, sendCh <-chan *pb.Report) error {
	ticker := time.NewTicker(c.cfg.HeartbeatInterval)
	defer ticker.Stop()
	drained := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := stream.Send(c.buildHeartbeat()); err != nil {
				return fmt.Errorf("发送心跳: %w", err)
			}
		case r, ok := <-sendCh:
			if !ok {
				return nil
			}
			if err := c.sendReport(stream, r); err != nil {
				// 业务上报失败 → 进离线队列等待补传（心跳/ACK 丢弃，靠协议重推机制补偿）
				if !isTransient(r) {
					if qerr := c.queue.Push(r); qerr != nil {
						c.log.Error("离线队列写入失败", "err", qerr)
					}
				}
				return fmt.Errorf("发送 Report: %w", err)
			}
		case r := <-c.pendingReports:
			// 资产快照等采集产物：优先于离线队列补传直接发出，失败同样入离线队列
			if err := c.sendReport(stream, r); err != nil {
				if qerr := c.queue.Push(r); qerr != nil {
					c.log.Error("离线队列写入失败", "err", qerr)
				}
				return fmt.Errorf("发送 Report: %w", err)
			}
		default:
			// 发送空闲且尚未补传 → 限速补传离线队列
			if !drained {
				if err := c.drainQueue(stream); err != nil {
					return err
				}
				drained = true
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// sendReport 发送单条 Report
func (c *Client) sendReport(stream pb.AgentChannel_ChannelClient, r *pb.Report) error {
	return stream.Send(r)
}

// drainQueue 补传离线队列（限速：DrainRatePerSec；未发出条目重新入队）
func (c *Client) drainQueue(stream pb.AgentChannel_ChannelClient) error {
	reports, err := c.queue.PopAll()
	if err != nil {
		c.log.Error("读取离线队列失败", "err", err)
		return nil // 队列读取失败不拆连接，下轮重试
	}
	if len(reports) == 0 {
		return nil
	}
	interval := time.Second / time.Duration(c.cfg.DrainRatePerSec)
	sent := 0
	for i, r := range reports {
		if err := stream.Send(r); err != nil {
			break
		}
		sent = i + 1
		time.Sleep(interval)
	}
	for _, r := range reports[sent:] {
		if qerr := c.queue.Push(r); qerr != nil {
			c.log.Error("离线队列回写失败", "err", qerr)
		}
	}
	if sent < len(reports) {
		return fmt.Errorf("补传中断，%d/%d 已发出", sent, len(reports))
	}
	c.log.Info("离线队列补传完成", "count", len(reports))
	return nil
}

// buildHeartbeat 构造心跳 Report
func (c *Client) buildHeartbeat() *pb.Report {
	s := identity.Sample()
	guardStatus := "normal"
	if c.grd != nil && c.grd.Isolated() {
		guardStatus = "isolated"
	}
	return &pb.Report{
		AgentId:  c.state.AgentID,
		ReportId: newUUID(),
		Ts:       time.Now().UnixMilli(),
		Payload: &pb.Report_Heartbeat{Heartbeat: &pb.RptHeartbeat{
			AgentVersion:  identity.AgentVersion,
			CpuUsage:      s.CpuUsage,
			MemUsage:      s.MemUsage,
			ProcessCount:  s.ProcessCount,
			UptimeSec:     s.UptimeSec,
			PolicyVersion: c.state.PolicyVersion,
			GuardStatus:   guardStatus,
			DbVersion:     virusscan.LocalVersion(c.workDir), // 落后即触发 CmdSignatureUpdate
		}},
	}
}

// wrapAck 将 RptAck 包装为 Report
func (c *Client) wrapAck(a *pb.RptAck) *pb.Report {
	return &pb.Report{
		AgentId:  c.state.AgentID,
		ReportId: newUUID(),
		Ts:       time.Now().UnixMilli(),
		Payload:  &pb.Report_Ack{Ack: a},
	}
}

// handleCommand 指令处理：幂等去重（§3.2）→ 执行 → 产出 ACK 序列
func (c *Client) handleCommand(cmd *pb.Command, sendCh chan<- *pb.Report, sctx context.Context) []*pb.RptAck {
	if cmd.GetCmdId() == "" {
		return nil
	}
	// 幂等：已处理过的指令直接重发上次 ACK
	if prev := c.dedup.Get(cmd.GetCmdId()); prev != nil {
		if terminal(prev) {
			return []*pb.RptAck{prev}
		}
		return []*pb.RptAck{prev}
	}
	acks := c.executeCommand(cmd, sendCh, sctx)
	for _, a := range acks {
		c.dedup.Put(cmd.GetCmdId(), a)
	}
	return acks
}

// executeCommand 指令执行：proto Command 全部 11 种 payload 均真实处理，
// default 分支仅为 proto 未来扩展的防御性兜底
func (c *Client) executeCommand(cmd *pb.Command, sendCh chan<- *pb.Report, sctx context.Context) []*pb.RptAck {
	received := &pb.RptAck{CmdId: cmd.GetCmdId(), Stage: pb.RptAck_RECEIVED, Code: 0}
	switch p := cmd.GetPayload().(type) {
	case *pb.Command_PolicySync:
		if policy := p.PolicySync.GetPolicyJson(); policy != "" {
			if err := c.applyPolicyJson(policy, true); err != nil {
				c.log.Error("策略同步失败", "policy_version", p.PolicySync.GetPolicyVersion(), "err", err)
				return []*pb.RptAck{received, {CmdId: cmd.GetCmdId(), Stage: pb.RptAck_FAILED, Code: 1,
					Message: "apply policy: " + err.Error()}}
			}
		}
		c.state.PolicyVersion = p.PolicySync.GetPolicyVersion()
		if err := c.state.Save(c.workDir); err != nil {
			c.log.Error("策略版本持久化失败", "err", err)
		}
		c.log.Info("策略已同步", "policy_version", c.state.PolicyVersion)
		return []*pb.RptAck{received, {CmdId: cmd.GetCmdId(), Stage: pb.RptAck_DONE, Code: 0,
			Message: "policy version " + c.state.PolicyVersion}}
	case *pb.Command_CollectNow:
		// 同步执行采集（采集耗时秒级，指令频率极低），完成后经当前连接直接上报
		names := p.CollectNow.GetCollectorNames()
		start := time.Now()
		snap := collector.SnapshotWithKubernetesNode(names, c.log, c.cfg.KubernetesNodeName)
		r := &pb.Report{
			AgentId:  c.state.AgentID,
			ReportId: newUUID(),
			Ts:       time.Now().UnixMilli(),
			Payload:  &pb.Report_Asset{Asset: snap},
		}
		select {
		case sendCh <- r:
		case <-sctx.Done():
		}
		return []*pb.RptAck{received, {CmdId: cmd.GetCmdId(), Stage: pb.RptAck_DONE, Code: 0,
			Message: fmt.Sprintf("collected sw=%d ports=%d accounts=%d disks=%d in %s",
				len(snap.GetSoftware()), len(snap.GetPorts()),
				len(snap.GetAccounts()), len(snap.GetDisks()), time.Since(start).Round(time.Millisecond))}}
	case *pb.Command_BaselineCheck:
		return c.executeBaselineCheck(p.BaselineCheck, received)
	case *pb.Command_VulnScan:
		return c.executeVulnScan(p.VulnScan, received)
	case *pb.Command_VirusScan:
		return c.executeVirusScan(p.VirusScan, received)
	case *pb.Command_VirusAction:
		return c.executeVirusAction(p.VirusAction, received)
	case *pb.Command_SignatureUpdate:
		return c.executeSignatureUpdate(p.SignatureUpdate, received, sctx)
	case *pb.Command_VulnFix:
		return c.executeVulnFix(p.VulnFix, received)
	case *pb.Command_ProtectAction:
		return c.executeProtectAction(p.ProtectAction, received)
	case *pb.Command_AgentUpgrade:
		// 灰度升级（docs/01 §6.4）：校验替换成功即 DONE，随后进程退出由 systemd/SCM 拉起新版本
		msg, err := upgrade.Apply(c.workDir, p.AgentUpgrade.GetDownloadUrl(), p.AgentUpgrade.GetSha256(), p.AgentUpgrade.GetVersion())
		if err != nil {
			return []*pb.RptAck{received, {CmdId: cmd.GetCmdId(), Stage: pb.RptAck_FAILED, Code: 1, Message: err.Error()}}
		}
		return []*pb.RptAck{received, {CmdId: cmd.GetCmdId(), Stage: pb.RptAck_DONE, Code: 0, Message: msg}}
	case *pb.Command_AgentControl:
		acks := []*pb.RptAck{received}
		done := func(msg string) *pb.RptAck {
			return &pb.RptAck{CmdId: cmd.GetCmdId(), Stage: pb.RptAck_DONE, Message: msg}
		}
		fail := func(msg string) *pb.RptAck {
			return &pb.RptAck{CmdId: cmd.GetCmdId(), Stage: pb.RptAck_FAILED, Code: 1, Message: msg}
		}
		switch p.AgentControl.GetAction() {
		case pb.CmdAgentControl_RESTART:
			// ACK 先行，2s 后自退出由 systemd/SCM 拉起（与升级同模式）
			go func() {
				time.Sleep(2 * time.Second)
				c.log.Info("收到 RESTART 指令，进程退出待服务管理器拉起")
				os.Exit(0)
			}()
			acks = append(acks, done("restarting"))
		case pb.CmdAgentControl_PAUSE_COLLECT:
			c.collectPaused.Store(true)
			acks = append(acks, done("collect paused"))
		case pb.CmdAgentControl_RESUME_COLLECT:
			c.collectPaused.Store(false)
			acks = append(acks, done("collect resumed"))
		case pb.CmdAgentControl_ARM_UNINSTALL:
			tok := p.AgentControl.GetUninstallToken()
			if len(tok) < 8 {
				acks = append(acks, fail("invalid uninstall token"))
				break
			}
			c.state.UninstallToken = tok
			c.state.UninstallExpire = time.Now().Add(15 * time.Minute).Unix()
			if err := c.state.Save(c.workDir); err != nil {
				acks = append(acks, fail("persist token: "+err.Error()))
				break
			}
			c.log.Warn("卸载口令已布防（15 分钟内有效，一次性）")
			acks = append(acks, done("uninstall token armed, valid 15m"))
		default:
			acks = append(acks, fail("unknown agent control action"))
		}
		return acks
	default:
		return []*pb.RptAck{received, {CmdId: cmd.GetCmdId(), Stage: pb.RptAck_FAILED, Code: 1,
			Message: fmt.Sprintf("cmd %T not implemented in M1", cmd.GetPayload())}}
	}
}

/* ==================== 勒索诱饵防护 ==================== */

// reportSecurityEvent guard 引擎事件上报回调：优先经活跃连接直发，断线期间入离线队列补传
func (c *Client) reportSecurityEvent(ev *pb.RptSecurityEvent) {
	c.pushReport(&pb.Report{
		AgentId:  c.state.AgentID,
		ReportId: newUUID(),
		Ts:       time.Now().UnixMilli(),
		Payload:  &pb.Report_SecurityEvent{SecurityEvent: ev},
	})
}

// executeProtectAction 安全处置指令：KILL_PROCESS（PID/路径）/ ISOLATE_HOST / RESTORE_ISOLATION
func (c *Client) executeProtectAction(pa *pb.CmdProtectAction, received *pb.RptAck) []*pb.RptAck {
	cmdID := received.GetCmdId()
	switch pa.GetAction() {
	case pb.CmdProtectAction_KILL_PROCESS:
		target := pa.GetTarget()
		var done bool
		var msg string
		if pid, err := strconv.ParseInt(target, 10, 32); err == nil {
			done = guard.KillProcess(int32(pid))
			msg = fmt.Sprintf("kill pid %s: %v", target, done)
		} else {
			n := guard.KillByPath(target)
			done = n > 0
			msg = fmt.Sprintf("kill by path %s: %d killed", target, n)
		}
		stage := pb.RptAck_DONE
		if !done {
			stage = pb.RptAck_FAILED
		}
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: stage, Code: 0, Message: msg}}
	case pb.CmdProtectAction_ISOLATE_HOST:
		if err := c.grd.IsolateHost(pa.GetReason()); err != nil {
			return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 1,
				Message: "isolate: " + err.Error()}}
		}
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_DONE, Code: 0,
			Message: "host isolated (agent channel only)"}}
	case pb.CmdProtectAction_RESTORE_ISOLATION:
		if err := c.grd.RestoreIsolation(); err != nil {
			return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 1,
				Message: "restore: " + err.Error()}}
		}
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_DONE, Code: 0,
			Message: "isolation restored"}}
	default:
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 1,
			Message: fmt.Sprintf("protect action %v not implemented", pa.GetAction())}}
	}
}

/* ==================== 基线核查 ==================== */

// executeBaselineCheck 基线核查指令：核查耗时可能达分钟级（cmd_output 逐项执行），
// 不能阻塞指令接收循环 —— 立即回 RECEIVED+RUNNING，goroutine 执行完成后经
// pendingReports 上报结果与终态 ACK（断线期间阻塞缓冲，重连后补发）。
func (c *Client) executeBaselineCheck(bc *pb.CmdBaselineCheck, received *pb.RptAck) []*pb.RptAck {
	cmdID := received.GetCmdId()
	if !c.baselineBusy.CompareAndSwap(false, true) {
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 2,
			Message: "已有基线核查任务执行中，请稍后重试"}}
	}
	running := &pb.RptAck{CmdId: cmdID, Stage: pb.RptAck_RUNNING, Code: 0,
		Message: fmt.Sprintf("baseline task %s running, %d items", bc.GetTaskId(), len(bc.GetItems()))}
	go func() {
		defer c.baselineBusy.Store(false)
		start := time.Now()
		result := baseline.Run(bc.GetTaskId(), bc.GetItems(), c.log)
		failed := 0
		for _, it := range result.GetItems() {
			if !it.GetPassed() {
				failed++
			}
		}
		stage, code, msg := pb.RptAck_DONE, int32(0),
			fmt.Sprintf("baseline task %s: %d items, %d failed, in %s",
				bc.GetTaskId(), len(result.GetItems()), failed, time.Since(start).Round(time.Millisecond))
		if len(result.GetItems()) == 0 {
			stage, code, msg = pb.RptAck_FAILED, int32(1), "baseline task "+bc.GetTaskId()+": no items"
		}
		finalAck := &pb.RptAck{CmdId: cmdID, Stage: stage, Code: code, Message: msg}
		// 终态 ACK 先落 dedup：若期间服务端重推指令可直接回终态，不重复执行
		c.dedup.Put(cmdID, finalAck)
		c.pushReport(&pb.Report{
			AgentId:  c.state.AgentID,
			ReportId: newUUID(),
			Ts:       time.Now().UnixMilli(),
			Payload:  &pb.Report_BaselineResult{BaselineResult: result},
		})
		c.pushReport(c.wrapAck(finalAck))
		c.log.Info("基线核查完成", "task", bc.GetTaskId(), "failed", failed)
	}()
	return []*pb.RptAck{received, running}
}

/* ==================== 安全扫描（弱口令/端口服务） ==================== */

// executeVulnScan 安全扫描指令：弱口令字典比对为 CPU 密集（shadow × top100），
// 与基线核查同模式异步执行 —— 立即回 RECEIVED+RUNNING，完成后上报结果与终态 ACK。
func (c *Client) executeVulnScan(vs *pb.CmdVulnScan, received *pb.RptAck) []*pb.RptAck {
	cmdID := received.GetCmdId()
	if !c.scanBusy.CompareAndSwap(false, true) {
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 2,
			Message: "已有扫描任务执行中，请稍后重试"}}
	}
	running := &pb.RptAck{CmdId: cmdID, Stage: pb.RptAck_RUNNING, Code: 0,
		Message: fmt.Sprintf("scan task %s running (weak_pwd=%v port_service=%v)",
			vs.GetTaskId(), vs.GetIncludeWeakPassword(), vs.GetIncludePortService())}
	go func() {
		defer c.scanBusy.Store(false)
		start := time.Now()
		result := scan.Run(vs.GetTaskId(), vs.GetIncludeWeakPassword(), vs.GetIncludePortService(), c.log)
		finalAck := &pb.RptAck{CmdId: cmdID, Stage: pb.RptAck_DONE, Code: 0,
			Message: fmt.Sprintf("scan task %s: weak_pwd=%d port_service=%d in %s",
				vs.GetTaskId(), len(result.GetWeakPasswords()), len(result.GetPortServices()),
				time.Since(start).Round(time.Millisecond))}
		// 终态 ACK 先落 dedup：服务端重推指令时直接回终态，不重复扫描
		c.dedup.Put(cmdID, finalAck)
		c.pushReport(&pb.Report{
			AgentId:  c.state.AgentID,
			ReportId: newUUID(),
			Ts:       time.Now().UnixMilli(),
			Payload:  &pb.Report_ScanResult{ScanResult: result},
		})
		c.pushReport(c.wrapAck(finalAck))
		c.log.Info("安全扫描完成", "task", vs.GetTaskId(),
			"weak_pwd", len(result.GetWeakPasswords()), "port_service", len(result.GetPortServices()))
	}()
	return []*pb.RptAck{received, running}
}

/* ==================== 病毒查杀 ==================== */

// executeVirusScan 病毒扫描指令：全盘遍历分钟~小时级，异步执行（同基线核查模式）。
// 检出默认隔离（docs/05 §1.4），结果经 pendingReports 上报 + 终态 ACK。
func (c *Client) executeVirusScan(vs *pb.CmdVirusScan, received *pb.RptAck) []*pb.RptAck {
	cmdID := received.GetCmdId()
	if !c.virusBusy.CompareAndSwap(false, true) {
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 2,
			Message: "已有病毒扫描任务执行中，请稍后重试"}}
	}
	running := &pb.RptAck{CmdId: cmdID, Stage: pb.RptAck_RUNNING, Code: 0,
		Message: fmt.Sprintf("virus task %s running (mode=%s paths=%d sigdb=%s)",
			vs.GetTaskId(), vs.GetMode().String(), len(vs.GetPaths()), virusscan.LocalVersion(c.workDir))}
	go func() {
		defer c.virusBusy.Store(false)
		start := time.Now()
		engine := virusscan.NewEngine(c.workDir, c.log)
		result := engine.Scan(vs.GetTaskId(), vs.GetMode(), vs.GetPaths(), c.workDir)
		stage, code, msg := pb.RptAck_DONE, int32(0),
			fmt.Sprintf("virus task %s: files=%d findings=%d quarantined=%d in %s",
				vs.GetTaskId(), result.GetFilesScanned(), len(result.GetFindings()),
				countAction(result, "quarantined"), time.Since(start).Round(time.Millisecond))
		if result.GetFilesScanned() == 0 {
			stage, code, msg = pb.RptAck_FAILED, int32(1),
				"virus task "+vs.GetTaskId()+": 特征库未安装或扫描范围为空"
		}
		finalAck := &pb.RptAck{CmdId: cmdID, Stage: stage, Code: code, Message: msg}
		c.dedup.Put(cmdID, finalAck)
		c.pushReport(&pb.Report{
			AgentId:  c.state.AgentID,
			ReportId: newUUID(),
			Ts:       time.Now().UnixMilli(),
			Payload:  &pb.Report_VirusResult{VirusResult: result},
		})
		c.pushReport(c.wrapAck(finalAck))
		c.log.Info("病毒扫描完成", "task", vs.GetTaskId(),
			"files", result.GetFilesScanned(), "findings", len(result.GetFindings()))
	}()
	return []*pb.RptAck{received, running}
}

// executeVirusAction 处置指令：隔离/删除/恢复均为本机文件操作（秒级），同步执行。
// WHITELIST 由平台全局生效（t_virus_whitelist），Agent 无需动作直接确认。
func (c *Client) executeVirusAction(va *pb.CmdVirusAction, received *pb.RptAck) []*pb.RptAck {
	cmdID := received.GetCmdId()
	q := virusscan.NewQuarantine(c.workDir)
	var ok, fail int
	var lastErr string
	for _, t := range va.GetTargets() {
		var err error
		switch va.GetAction() {
		case pb.CmdVirusAction_QUARANTINE:
			err = q.QuarantineFile(t.GetPath())
		case pb.CmdVirusAction_DELETE:
			err = q.Delete(t.GetPath())
		case pb.CmdVirusAction_RESTORE:
			err = q.Restore(t.GetPath())
		case pb.CmdVirusAction_WHITELIST:
			// 平台侧白名单表已生效，Agent 端无动作
		default:
			err = fmt.Errorf("未知处置动作 %v", va.GetAction())
		}
		if err != nil {
			fail++
			lastErr = err.Error()
			c.log.Warn("病毒处置失败", "action", va.GetAction().String(), "path", t.GetPath(), "err", err)
		} else {
			ok++
		}
	}
	if fail > 0 {
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 1,
			Message: fmt.Sprintf("action %s: ok=%d fail=%d last_err=%s",
				va.GetAction().String(), ok, fail, lastErr)}}
	}
	return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_DONE, Code: 0,
		Message: fmt.Sprintf("action %s: ok=%d", va.GetAction().String(), ok)}}
}

// executeSignatureUpdate 特征库更新指令：限速下载 + sha256 校验 + 原子替换。
// 下载分钟级（20MB @2MB/s），异步执行；完成后热重载特征库。
func (c *Client) executeSignatureUpdate(su *pb.CmdSignatureUpdate, received *pb.RptAck, sctx context.Context) []*pb.RptAck {
	cmdID := received.GetCmdId()
	// 版本比对：本地已是目标版本则幂等跳过（服务端重推场景）
	if virusscan.LocalVersion(c.workDir) == su.GetDbVersion() {
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_DONE, Code: 0,
			Message: "already at " + su.GetDbVersion()}}
	}
	if !c.sigBusy.CompareAndSwap(false, true) {
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 2,
			Message: "特征库更新进行中"}}
	}
	running := &pb.RptAck{CmdId: cmdID, Stage: pb.RptAck_RUNNING, Code: 0,
		Message: "downloading " + su.GetDbVersion()}
	go func() {
		defer c.sigBusy.Store(false)
		err := virusscan.UpdateDB(sctx, c.workDir, su.GetDownloadUrl(), su.GetSha256(), c.log)
		stage, code, msg := pb.RptAck_DONE, int32(0), "updated to "+su.GetDbVersion()
		if err != nil {
			stage, code, msg = pb.RptAck_FAILED, int32(1), "update failed: "+err.Error()
			c.log.Error("特征库更新失败", "target", su.GetDbVersion(), "err", err)
		} else {
			// 热重载内存态特征库（下次扫描即用新库）
			virusscan.ReloadDB(c.workDir)
		}
		finalAck := &pb.RptAck{CmdId: cmdID, Stage: stage, Code: code, Message: msg}
		c.dedup.Put(cmdID, finalAck)
		c.pushReport(c.wrapAck(finalAck))
	}()
	return []*pb.RptAck{received, running}
}

// countAction 统计指定处置动作的 finding 数
func countAction(r *pb.RptVirusResult, action string) int {
	n := 0
	for _, f := range r.GetFindings() {
		if f.GetActionTaken() == action {
			n++
		}
	}
	return n
}

/* ==================== 配置类一键修复 ==================== */

// executeVulnFix 配置修复指令：文件写入 + 可能的服务操作，异步执行（同基线核查模式），
// 完成后上报 RptFixResult 与终态 ACK。单项失败自动回滚，不影响其余项。
func (c *Client) executeVulnFix(vf *pb.CmdVulnFix, received *pb.RptAck) []*pb.RptAck {
	cmdID := received.GetCmdId()
	if !c.fixBusy.CompareAndSwap(false, true) {
		return []*pb.RptAck{received, {CmdId: cmdID, Stage: pb.RptAck_FAILED, Code: 2,
			Message: "已有修复任务执行中，请稍后重试"}}
	}
	running := &pb.RptAck{CmdId: cmdID, Stage: pb.RptAck_RUNNING, Code: 0,
		Message: fmt.Sprintf("fix task %s running, %d items", vf.GetTaskId(), len(vf.GetFixes()))}
	go func() {
		defer c.fixBusy.Store(false)
		start := time.Now()
		result := fixer.Run(vf.GetTaskId(), vf.GetFixes(), c.workDir, c.log)
		var failed, rolled int
		for _, r := range result.GetResults() {
			if !r.GetSuccess() {
				failed++
				if r.GetRolledBack() {
					rolled++
				}
			}
		}
		stage, code := pb.RptAck_DONE, int32(0)
		if len(result.GetResults()) == 0 {
			stage, code = pb.RptAck_FAILED, int32(1)
		}
		finalAck := &pb.RptAck{CmdId: cmdID, Stage: stage, Code: code,
			Message: fmt.Sprintf("fix task %s: %d items, %d failed (%d rolled back), in %s",
				vf.GetTaskId(), len(result.GetResults()), failed, rolled,
				time.Since(start).Round(time.Millisecond))}
		c.dedup.Put(cmdID, finalAck)
		c.pushReport(&pb.Report{
			AgentId:  c.state.AgentID,
			ReportId: newUUID(),
			Ts:       time.Now().UnixMilli(),
			Payload:  &pb.Report_FixResult{FixResult: result},
		})
		c.pushReport(c.wrapAck(finalAck))
		c.log.Info("配置修复完成", "task", vf.GetTaskId(), "failed", failed, "rolled_back", rolled)
	}()
	return []*pb.RptAck{received, running}
}

func (c *Client) pushReport(r *pb.Report) {
	c.reportMu.Lock()
	defer c.reportMu.Unlock()
	if c.channelActive {
		select {
		case c.pendingReports <- r:
			return
		default:
		}
	}
	c.persistReport(r)
}

// Disconnect after the sender stops, then persist anything it did not consume.
func (c *Client) setChannelActive(active bool) {
	c.reportMu.Lock()
	defer c.reportMu.Unlock()
	c.channelActive = active
	if active {
		return
	}
	for {
		select {
		case r := <-c.pendingReports:
			if r.GetMetrics() == nil && !isTransient(r) {
				c.persistReport(r)
			}
		default:
			return
		}
	}
}

func (c *Client) persistReport(r *pb.Report) {
	if err := c.queue.Push(r); err != nil {
		c.log.Error("业务上报入离线队列失败", "err", err)
	}
}

/* ==================== 资产采集 ==================== */

// minCollectGap 两次全量采集的最小间隔（防连接抖动触发重复采集）
const minCollectGap = 10 * time.Minute

// collectLoop 周期采集：定时全量 + triggerCollect 即时触发；产物经 pendingReports 由活跃连接发出
func (c *Client) collectLoop(ctx context.Context) {
	// 启动延迟：给首个连接留出建立时间，避免首采产物在断线期占满缓冲
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(c.cfg.CollectInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.triggerCollect(nil)
		case <-ticker.C:
			c.triggerCollect(nil)
		case names := <-c.collectTrigger:
			if c.collectPaused.Load() {
				c.log.Info("采集已暂停（CmdAgentControl.PAUSE_COLLECT），跳过本轮")
				continue
			}
			start := time.Now()
			snap := collector.SnapshotWithKubernetesNode(names, c.log, c.cfg.KubernetesNodeName)
			c.lastCollectAt = start
			c.pushReport(&pb.Report{
				AgentId:  c.state.AgentID,
				ReportId: newUUID(),
				Ts:       time.Now().UnixMilli(),
				Payload:  &pb.Report_Asset{Asset: snap},
			})
		}
	}
}

// triggerCollect 非阻塞触发采集（空 names = 全部）；距上次采集不足 minCollectGap 时跳过
func (c *Client) triggerCollect(names []string) {
	if time.Since(c.lastCollectAt) < minCollectGap {
		return
	}
	select {
	case c.collectTrigger <- names:
	default:
	}
}

/* ==================== 指标 / 日志采集 ==================== */

// metricsLoop 指标采集（docs/03 §3.1）：快组 10s / 慢组 60s。
// 指标为可丢弃数据：缓冲满直接丢（不入离线队列，断网期指标不保全，安全事件才保全）。
func (c *Client) metricsLoop(ctx context.Context) {
	fast := time.NewTicker(10 * time.Second)
	slow := time.NewTicker(60 * time.Second)
	defer fast.Stop()
	defer slow.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-fast.C:
			c.pushMetrics(sysmetrics.CollectFast(c.log))
		case <-slow.C:
			c.pushMetrics(sysmetrics.CollectSlow(c.log))
		}
	}
}

func (c *Client) pushMetrics(samples []*pb.MetricSample) {
	if len(samples) == 0 {
		return
	}
	r := &pb.Report{
		AgentId:  c.state.AgentID,
		ReportId: newUUID(),
		Ts:       time.Now().UnixMilli(),
		Payload:  &pb.Report_Metrics{Metrics: &pb.RptMetricsBatch{Samples: samples}},
	}
	select {
	case c.pendingReports <- r:
	default: // 缓冲满：丢弃本轮指标（可再生的低价值数据）
	}
}

// logLoop 登录/安全日志采集（docs/04 §2）：Agent 侧批量攒行 → RptLogBatch。
// 日志含入侵检测线索，经 pushReport 走离线队列保全路径。
func (c *Client) logLoop(ctx context.Context) {
	lc := logcollect.New(c.workDir, c.log, func(source string, lines []*pb.LogLine) {
		c.grd.ObserveLoginLogs(source, lines)
		c.pushReport(&pb.Report{
			AgentId:  c.state.AgentID,
			ReportId: newUUID(),
			Ts:       time.Now().UnixMilli(),
			Payload:  &pb.Report_LogBatch{LogBatch: &pb.RptLogBatch{Source: source, Lines: lines}},
		})
	})
	lc.Run(ctx)
}

/* ==================== TLS ==================== */

// mtlsConfig 加载证书构建 mTLS 客户端 TLS 配置（CN=agent_id）
func (c *Client) mtlsConfig() (*tls.Config, error) {
	certPath, keyPath, caPath := certPaths(c.workDir)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("加载客户端证书: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("加载平台 CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("平台 CA 证书解析失败")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   c.cfg.ServerNameOverride,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

/* ==================== 工具 ==================== */

// isTransient 心跳与 ACK 不入离线队列（靠服务端重推/下一心跳补偿）
func isTransient(r *pb.Report) bool {
	switch r.GetPayload().(type) {
	case *pb.Report_Heartbeat, *pb.Report_Ack:
		return true
	}
	return false
}

// jitter 退避加 ±20% 抖动（协议设计 §5）
func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41)) // 0..40
	if err != nil {
		return d
	}
	delta := time.Duration(float64(d) * 0.2 * (float64(n.Int64()) - 20) / 20)
	return d + delta
}

// newUUID v4
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
