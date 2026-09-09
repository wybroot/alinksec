// Package guard 勒索诱饵防护引擎（docs/05 §2）。
// 双触发：① 诱饵篡改（高置信，60s 健康检查） ② 加密速率行为（10s 快照对比）。
// 本地响应链：归因 → kill → 隔离（放行管控通道）→ 取证 → 事件上报。
// Agent 离线时全链路本地执行，事件入离线队列补传。
package guard

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/proto"
)

const (
	healthInterval = 60 * time.Second // 诱饵健康检查周期
	ruleDecoyID    = "PR-0010"        // docs/03 内置规则：诱饵防护
	ruleDecoyName  = "勒索诱饵防护"
	ruleRateID     = "PR-0011" // 内置规则：加密行为分析
	ruleRateName   = "加密行为分析"
)

// ReportFunc 安全事件上报回调（comm 注入，负责在线直发/离线入队）
type ReportFunc func(ev *proto.RptSecurityEvent)

// Guard 引擎实例
type Guard struct {
	cfg     *config.DecoyConfig // 受 mu 保护；策略热更新（PolicySync）原指针替换
	workDir string
	log     *slog.Logger
	report  ReportFunc

	mu            sync.Mutex
	isolated      bool // 当前隔离状态（marker 持久化）
	processRules  []config.ProcessRule
	processSeen   map[int32]int64 // pid -> create time; prevents PID reuse from being missed
	watchDirs     []string
	serverAddrVal string         // gRPC 连接地址（comm 注入，隔离放行解析用）
	virusCheck    VirusCheckFunc // 实时防护检查回调（comm 注入，virusmon.go）

	ratePrev map[string]treeSnapshot // 各监测树上一快照
}

// New 构建引擎并完成初始投放
func New(cfg *config.DecoyConfig, processRules []config.ProcessRule, workDir string, log *slog.Logger, report ReportFunc) *Guard {
	return &Guard{
		cfg:          cfg,
		workDir:      workDir,
		log:          log,
		report:       report,
		processRules: append([]config.ProcessRule(nil), processRules...),
		processSeen:  map[int32]int64{},
		ratePrev:     map[string]treeSnapshot{},
	}
}

// cur 当前配置快照（值拷贝；多 goroutine 读安全）
func (g *Guard) cur() config.DecoyConfig {
	g.mu.Lock()
	defer g.mu.Unlock()
	return *g.cfg
}

// UpdatePolicy 平台策略热更新（PolicySync）：替换配置 → 新目录补投 → 速率基线重置
func (g *Guard) UpdatePolicy(cfg *config.DecoyConfig, processRules []config.ProcessRule) {
	if cfg == nil {
		return
	}
	cfg.Normalize()
	g.mu.Lock()
	g.cfg = cfg
	g.processRules = append([]config.ProcessRule(nil), processRules...)
	// Rules apply to future execs. Re-baselining prevents retroactive actions
	// against already-running business processes after a policy edit.
	g.processSeen = map[int32]int64{}
	g.mu.Unlock()

	if cfg.Enabled == nil || *cfg.Enabled {
		dirs := g.deployDirs()
		g.mu.Lock()
		g.watchDirs = dirs
		g.mu.Unlock()
		created := newDecoyManager(cfg, g.workDir).ensureDeployed(dirs)
		g.log.Info("策略热更新生效", "dirs", len(dirs), "补投", created,
			"response", cfg.Response, "window_sec", cfg.RateWindowSec)
	} else {
		g.log.Info("策略热更新生效：诱饵防护已关闭")
	}
	g.ratePrev = map[string]treeSnapshot{} // 基线重置，避免目录/窗口切换误报
	g.seedProcessBaseline()
}

// Run 主循环：初始投放 → 并行跑健康检查（60s）与速率监测（窗口周期）
func (g *Guard) Run(ctx context.Context) {
	// 隔离残留：marker 存在则恢复隔离状态（与诱饵开关无关，防火墙规则可能已随重启丢失）
	g.recoverIsolationMarker()

	g.initialDeploy()

	healthTick := time.NewTicker(healthInterval)
	rateWindow := time.Duration(g.cur().RateWindowSec) * time.Second
	rateTick := time.NewTicker(rateWindow)
	defer healthTick.Stop()
	defer rateTick.Stop()
	g.seedProcessBaseline()
	processTick := time.NewTicker(processScanInterval)
	defer processTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-healthTick.C:
			g.healthLoop()
		case <-rateTick.C:
			g.rateLoop()
		case <-processTick.C:
			g.processLoop()
		}
		// 策略热更新可能改变监测窗口：不一致则重建 ticker
		if w := time.Duration(g.cur().RateWindowSec) * time.Second; w != rateWindow && w > 0 {
			rateWindow = w
			rateTick.Reset(w)
			g.log.Info("速率监测窗口已调整", "window", w.String())
		}
	}
}

// initialDeploy 启动投放（未启用则跳过；enabled 由热下发开启的场景由 UpdatePolicy 补投）
func (g *Guard) initialDeploy() {
	c := g.cur()
	if c.Enabled != nil && !*c.Enabled {
		g.log.Info("诱饵防护未启用（本地配置关闭，等待平台策略开启）")
		return
	}
	dirs := g.deployDirs()
	g.mu.Lock()
	g.watchDirs = dirs
	g.mu.Unlock()
	created := newDecoyManager(&c, g.workDir).ensureDeployed(dirs)
	g.log.Info("诱饵投放完成", "dirs", len(dirs), "decoys", created)
}

// healthLoop 诱饵健康检查：篡改 → 响应链（decoy_tamper）；丢失 → 低危事件 + 补投
func (g *Guard) healthLoop() {
	c := g.cur()
	if c.Enabled != nil && !*c.Enabled {
		return
	}
	dm := newDecoyManager(&c, g.workDir)
	res := dm.healthCheck()

	if len(res.Tampered) > 0 {
		g.log.Error("诱饵篡改，触发本地响应", "count", len(res.Tampered), "paths", res.Tampered)
		ev := g.respond("decoy_tampered", ruleDecoyID, ruleDecoyName, res.Tampered, res.Tampered)
		if g.report != nil {
			g.report(ev)
		}
		return // 响应链内已取证
	}

	if len(res.Missing) > 0 {
		// 丢失多为正常清理/重装：低危观察事件，不触发响应
		g.log.Warn("诱饵丢失，补投并低危上报", "count", len(res.Missing))
		if g.report != nil {
			g.report(&proto.RptSecurityEvent{
				RuleId:   ruleDecoyID,
				RuleName: ruleDecoyName,
				Type:     "decoy_tamper",
				Severity: proto.Severity_SEV_INFO,
				Detail:   mustJSON(map[string]any{"trigger": "decoy_missing", "paths": res.Missing}),
				EventTs:  time.Now().UnixMilli(),
			})
		}
		dm.ensureDeployed(g.watchDirs)
	}
}

// rateLoop 速率行为监测：触发 → 响应链（ransom_behavior）
func (g *Guard) rateLoop() {
	c := g.cur()
	if c.Enabled != nil && !*c.Enabled {
		return
	}
	// 监测树 = 配置 WatchTrees 或投放目录（热更新后实时生效）
	trees := c.WatchTrees
	if len(trees) == 0 {
		trees = g.deployDirs()
	}
	var (
		merged    *rateResult
		trigPaths []string
	)
	for _, t := range trees {
		cur := snapshotTree(t)
		if prev, ok := g.ratePrev[t]; ok {
			r := diffSnapshot(prev, cur)
			if merged == nil {
				merged = r
			} else {
				merged.Modified = append(merged.Modified, r.Modified...)
				merged.Created = append(merged.Created, r.Created...)
				merged.Vanished = append(merged.Vanished, r.Vanished...)
				merged.Renames += r.Renames
				merged.ExtChanges += r.ExtChanges
				merged.Churn += r.Churn
			}
		}
		g.ratePrev[t] = cur
	}
	if merged == nil {
		return
	}
	// 病毒实时防护：窗口内新增/修改文件 L1 检查（与速率触发独立，未触发也检查）
	g.virusSweep(append(append([]string{}, merged.Modified...), merged.Created...))

	if !merged.triggered(c.RateThreshold, c.ExtChangeRatio) {
		return
	}
	// 触发素材：写入文件 + 改名后新文件（归因用）
	trigPaths = append(trigPaths, merged.Modified...)
	trigPaths = append(trigPaths, merged.Created...)
	g.log.Error("加密速率行为触发本地响应", "churn", merged.Churn,
		"renames", merged.Renames, "ext_changes", merged.ExtChanges)
	ev := g.respond("ransom_rate", ruleRateID, ruleRateName, nil, trigPaths)
	if g.report != nil {
		g.report(ev)
	}
	// 触发后重置基线，避免持续告警风暴
	g.ratePrev = map[string]treeSnapshot{}
}

/* ---- 隔离 / 恢复 ---- */

// isolateMarker 隔离标记内容
type isolateMarker struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
}

// IsolateHost 主机隔离：先确保管控通道放行（server IP 解析失败则拒绝隔离，防失联）；
// comm 的 CmdProtectAction(ISOLATE_HOST) 与本地响应链共用
func (g *Guard) IsolateHost(reason string) error {
	ip := g.resolveServerIP()
	if ip == "" {
		return errNoServerIP
	}
	if err := isolatePlatform(ip); err != nil {
		return err
	}
	g.mu.Lock()
	g.isolated = true
	g.mu.Unlock()
	m, _ := json.Marshal(isolateMarker{Since: time.Now(), Reason: reason})
	_ = os.WriteFile(filepath.Join(g.workDir, "isolated.json"), m, 0600)
	g.log.Warn("主机已隔离", "reason", reason, "server_ip", ip)
	return nil
}

// RestoreIsolation 解除隔离（comm 的 CmdProtectAction RESTORE_ISOLATION 调用）
func (g *Guard) RestoreIsolation() error {
	err := restorePlatform()
	g.mu.Lock()
	g.isolated = false
	g.mu.Unlock()
	_ = os.Remove(filepath.Join(g.workDir, "isolated.json"))
	g.log.Info("主机隔离已解除")
	return err
}

// Isolated 当前隔离状态（心跳 guard_status 上报用）
func (g *Guard) Isolated() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.isolated
}

// recoverIsolationMarker 启动时发现 marker：说明隔离后重启过，防火墙规则可能丢失 → 重新隔离
func (g *Guard) recoverIsolationMarker() {
	b, err := os.ReadFile(filepath.Join(g.workDir, "isolated.json"))
	if err != nil {
		return
	}
	var m isolateMarker
	_ = json.Unmarshal(b, &m)
	g.mu.Lock()
	g.isolated = true
	g.mu.Unlock()
	if ip := g.resolveServerIP(); ip != "" {
		if err := isolatePlatform(ip); err != nil {
			g.log.Error("重启后重新隔离失败", "err", err)
		} else {
			g.log.Warn("检测到隔离 marker，重启后已重新隔离", "since", m.Since.Format(time.RFC3339))
		}
	}
}

// resolveServerIP 解析 server 地址为 IP（隔离放行必需；域名解析失败返回空）
func (g *Guard) resolveServerIP() string {
	cfg := g.serverAddr()
	host, _, err := net.SplitHostPort(cfg)
	if err != nil {
		host = cfg
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	if addrs, err := net.LookupIP(host); err == nil && len(addrs) > 0 {
		return addrs[0].String()
	}
	return ""
}

var errNoServerIP = &isolateErr{}

type isolateErr struct{}

func (*isolateErr) Error() string {
	return "server 地址无法解析为 IP，拒绝隔离以防管控通道失联"
}

// serverAddr 从全局配置读连接地址（由 comm 启动时通过 SetServerAddr 注入，避免 guard 依赖完整 Config）
func (g *Guard) serverAddr() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.serverAddrVal
}

// SetServerAddr comm 启动时注入 gRPC 连接地址
func (g *Guard) SetServerAddr(addr string) {
	g.mu.Lock()
	g.serverAddrVal = addr
	g.mu.Unlock()
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
