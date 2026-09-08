// Package collector 资产快照采集（跨平台：Linux / Windows）。
//
// 采集项：software / ports / processes / accounts / disks。
// 设计要点（04-Agent 设计与策略规范 §采集器）：
//   - 只读采集，任何单项失败不影响其余项；
//   - 端口/磁盘走 gopsutil（Linux 读 /proc 与 statfs，Windows 走系统 API）；
//   - 软件/账号为平台差异项，以 build tags 分文件实现。
package collector

import (
	"log/slog"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// task 单项采集任务（collector name → 填充函数）
type task struct {
	name string
	fn   func(*pb.RptAssetSnapshot)
}

var tasks = []task{
	{"software", collectSoftware},
	{"ports", collectPorts},
	{"processes", collectProcesses},
	{"accounts", collectAccounts},
	{"disks", collectDisks},
	{"containers", collectContainers},
}

// Snapshot 执行采集并组装快照；names 为空 = 全部，否则只跑指定采集器。
func Snapshot(names []string, log *slog.Logger) *pb.RptAssetSnapshot {
	return SnapshotWithKubernetesNode(names, log, "")
}

// SnapshotWithKubernetesNode collects host assets. Kubernetes data is limited to
// workloads scheduled on kubernetesNodeName (or the local hostname when empty),
// so a cluster-wide kubectl context never becomes a host asset snapshot.
func SnapshotWithKubernetesNode(names []string, log *slog.Logger, kubernetesNodeName string) *pb.RptAssetSnapshot {
	snap := &pb.RptAssetSnapshot{}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.TrimSpace(n)] = true
	}
	for _, t := range tasks {
		if len(want) > 0 && !want[t.name] {
			continue
		}
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error("采集器异常", "collector", t.name, "panic", r)
				}
			}()
			if t.name == "containers" {
				collectContainersForNode(snap, kubernetesNodeName)
			} else {
				t.fn(snap)
			}
		}()
		log.Info("采集完成",
			"collector", t.name,
			"software", len(snap.GetSoftware()),
			"ports", len(snap.GetPorts()),
			"processes", len(snap.GetProcesses()),
			"accounts", len(snap.GetAccounts()),
			"disks", len(snap.GetDisks()),
			"duration", time.Since(start).Round(time.Millisecond))
	}
	return snap
}

/* ==================== 端口（gopsutil 跨平台） ==================== */

// collectPorts 采集监听端口：TCP 仅 LISTEN；UDP 为本地绑定（无状态语义）。
// pid → 进程名做会话内缓存，避免对同一 pid 反复查询。
func collectPorts(snap *pb.RptAssetSnapshot) {
	conns, err := gnet.Connections("inet")
	if err != nil {
		return
	}
	nameCache := make(map[int32]string)
	for _, c := range conns {
		isUDP := c.Type == syscall.SOCK_DGRAM
		if !isUDP && c.Status != "LISTEN" {
			continue
		}
		proto := "tcp"
		if isUDP {
			proto = "udp"
		}
		if strings.Contains(c.Laddr.IP, ":") && !strings.Contains(c.Laddr.IP, ".") {
			proto += "6"
		}
		snap.Ports = append(snap.Ports, &pb.PortInfo{
			Port:     uint32(c.Laddr.Port),
			Protocol: proto,
			Process:  procName(c.Pid, nameCache),
			BindAddr: c.Laddr.IP,
		})
	}
}

// procName pid → 进程名（带缓存；查询失败返回空串）
func procName(pid int32, cache map[int32]string) string {
	if pid <= 0 {
		return ""
	}
	if n, ok := cache[pid]; ok {
		return n
	}
	name := ""
	if p, err := process.NewProcess(pid); err == nil {
		if n, err := p.Name(); err == nil {
			name = n
		}
	}
	cache[pid] = name
	return name
}

func collectProcesses(snap *pb.RptAssetSnapshot) {
	procs, err := process.Processes()
	if err != nil {
		return
	}
	for _, p := range procs {
		name, _ := p.Name()
		exe, _ := p.Exe()
		args, _ := p.CmdlineSlice()
		user, _ := p.Username()
		var rss uint64
		if mem, err := p.MemoryInfo(); err == nil && mem != nil {
			rss = mem.RSS
		}
		snap.Processes = append(snap.Processes, &pb.ProcessInfo{Pid: p.Pid, Name: name, Exe: exe, Cmdline: redactCommandLine(args), User: user, RssBytes: rss})
	}
}

func redactCommandLine(args []string) string {
	redacted := append([]string(nil), args...)
	for i, arg := range redacted {
		lower := strings.ToLower(arg)
		for _, key := range []string{"password", "passwd", "token", "secret", "api-key", "apikey"} {
			if strings.HasPrefix(lower, "--"+key+"=") || strings.HasPrefix(lower, "-"+key+"=") {
				redacted[i] = arg[:strings.Index(arg, "=")+1] + "***"
			}
			if (lower == "--"+key || lower == "-"+key) && i+1 < len(redacted) {
				redacted[i+1] = "***"
			}
		}
	}
	return strings.Join(redacted, " ")
}

/* ==================== 磁盘（gopsutil 跨平台） ==================== */

// collectDisks 采集物理文件系统容量（Linux 过滤 /proc /sys 等虚拟挂载）
func collectDisks(snap *pb.RptAssetSnapshot) {
	parts, err := disk.Partitions(false) // false = 仅物理文件系统
	if err != nil {
		return
	}
	for _, p := range parts {
		u, err := disk.Usage(p.Mountpoint)
		if err != nil || u.Total == 0 {
			continue
		}
		snap.Disks = append(snap.Disks, &pb.DiskInfo{
			Mount:      p.Mountpoint,
			FsType:     p.Fstype,
			TotalBytes: u.Total,
			UsedBytes:  u.Used,
		})
	}
}
