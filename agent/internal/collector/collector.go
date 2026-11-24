// Package collector 资产快照采集（跨平台：Linux / Windows）。
//
// 采集项：software / ports / processes / accounts / disks。
// 设计要点（04-Agent 设计与策略规范 §采集器）：
//   - 只读采集，任何单项失败不影响其余项；
//   - 端口/磁盘走 gopsutil（Linux 读 /proc 与 statfs，Windows 走系统 API）；
//   - 软件/账号为平台差异项，以 build tags 分文件实现。
package collector

import (
	"errors"
	"log/slog"
	"os"
	"os/user"
	"runtime"
	"strconv"
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
	for _, t := range selectedTasks(names) {
		snap.Collected = append(snap.Collected, t.name)
		collectionStatus(snap, t.name, pb.AssetCollection_COMPLETE, "")
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					collectionStatus(snap, t.name, pb.AssetCollection_FAILED, "collector_panic")
					if t.name == "software" {
						snap.Software = nil
						snap.SoftwareInventory = &pb.SoftwareInventory{Status: pb.SoftwareInventory_FAILED, Error: "collector_panic"}
					}
					log.Error("采集器异常", "collector", t.name, "panic", r)
				}
			}()
			if t.name == "containers" {
				collectContainersForNode(snap, kubernetesNodeName)
			} else {
				t.fn(snap)
			}
		}()
		if t.name == "software" && snap.SoftwareInventory != nil {
			status := pb.AssetCollection_COMPLETE
			if snap.SoftwareInventory.Status == pb.SoftwareInventory_FAILED {
				status = pb.AssetCollection_FAILED
			}
			if snap.SoftwareInventory.Status == pb.SoftwareInventory_UNSUPPORTED {
				status = pb.AssetCollection_UNSUPPORTED
			}
			collectionStatus(snap, t.name, status, snap.SoftwareInventory.Error)
		}
		log.Info("采集完成",
			"collector", t.name,
			"software", len(snap.GetSoftware()),
			"ports", len(snap.GetPorts()),
			"processes", len(snap.GetProcesses()),
			"accounts", len(snap.GetAccounts()),
			"disks", len(snap.GetDisks()),
			"containers", len(snap.GetContainers()),
			"duration", time.Since(start).Round(time.Millisecond))
	}
	return snap
}

// ValidNames rejects an unsupported targeted request instead of emitting an
// empty legacy-looking snapshot that could clear unrelated assets.
func ValidNames(names []string) bool {
	if len(names) > len(tasks) {
		return false
	}
	for _, name := range names {
		known := false
		for _, task := range tasks {
			if strings.TrimSpace(name) == task.name {
				known = true
				break
			}
		}
		if !known {
			return false
		}
	}
	return true
}

func selectedTasks(names []string) []task {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.TrimSpace(n)] = true
	}
	selected := make([]task, 0, len(tasks))
	for _, t := range tasks {
		if len(want) > 0 && !want[t.name] {
			continue
		}
		selected = append(selected, t)
	}
	return selected
}

/* ==================== 端口（gopsutil 跨平台） ==================== */

var errEmptyProcessName = errors.New("empty process name")

// isPermissionError classifies OS/gopsutil permission failures across wrapped strings.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) || errors.Is(err, process.ErrorNotPermitted) ||
		errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "operation not permitted")
}

// isProcessGoneError distinguishes transient exited processes from readable privilege errors.
func isProcessGoneError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, process.ErrorProcessNotRunning) || errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "process does not exist") ||
		strings.Contains(msg, "no such process")
}

func isWindowsKernelPseudoProcess(pid int32) bool {
	return runtime.GOOS == "windows" && (pid == 0 || pid == 4)
}

type portProcCacheEntry struct {
	name string
	err  error
}

func defaultLookupPortProcess(pid int32) (string, error) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return "", err
	}
	name, err := p.Name()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(name) == "" {
		return "", errEmptyProcessName
	}
	return name, nil
}

var lookupPortProcess = defaultLookupPortProcess

// collectPorts 采集监听端口：TCP 仅 LISTEN；UDP 为本地绑定（无状态语义）。
// pid → 进程名做会话内缓存（包含失败结论），避免重复查询且保留缺漏原因。
func collectPorts(snap *pb.RptAssetSnapshot) {
	conns, err := listConnections("inet")
	if err != nil {
		collectionStatus(snap, "ports", pb.AssetCollection_FAILED, "enumeration_failed")
		return
	}
	cache := make(map[int32]portProcCacheEntry)
	var permDenied, unattributed, lookupFailed bool
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
		proc := ""
		if c.Pid <= 0 {
			unattributed = true
		} else {
			entry, ok := cache[c.Pid]
			if !ok {
				n, lookupErr := lookupPortProcess(c.Pid)
				entry = portProcCacheEntry{name: n, err: lookupErr}
				cache[c.Pid] = entry
			}
			proc = entry.name
			if entry.err != nil {
				if isPermissionError(entry.err) {
					permDenied = true
				} else {
					lookupFailed = true
				}
			}
		}
		snap.Ports = append(snap.Ports, &pb.PortInfo{
			Port:     uint32(c.Laddr.Port),
			Protocol: proto,
			Process:  proc,
			BindAddr: c.Laddr.IP,
		})
	}
	switch {
	case permDenied:
		collectionStatus(snap, "ports", pb.AssetCollection_PARTIAL, "port_process_permission_denied")
	case unattributed:
		collectionStatus(snap, "ports", pb.AssetCollection_PARTIAL, "port_process_unattributed")
	case lookupFailed:
		collectionStatus(snap, "ports", pb.AssetCollection_PARTIAL, "port_process_lookup_failed")
	}
}

type processReader interface {
	PID() int32
	Name() (string, error)
	Exe() (string, error)
	CmdlineSlice() ([]string, error)
	Username() (string, error)
	MemoryInfo() (*process.MemoryInfoStat, error)
}

type gopsutilProcess struct {
	p *process.Process
}

func (g gopsutilProcess) PID() int32                                  { return g.p.Pid }
func (g gopsutilProcess) Name() (string, error)                       { return g.p.Name() }
func (g gopsutilProcess) Exe() (string, error)                        { return g.p.Exe() }
func (g gopsutilProcess) CmdlineSlice() ([]string, error)             { return g.p.CmdlineSlice() }
func (g gopsutilProcess) Username() (string, error)                   { return g.p.Username() }
func (g gopsutilProcess) MemoryInfo() (*process.MemoryInfoStat, error) { return g.p.MemoryInfo() }

func defaultListProcessReaders() ([]processReader, error) {
	procs, err := listProcesses()
	if err != nil {
		return nil, err
	}
	readers := make([]processReader, 0, len(procs))
	for _, p := range procs {
		if p != nil {
			readers = append(readers, gopsutilProcess{p: p})
		}
	}
	return readers, nil
}

var listProcessReaders = defaultListProcessReaders

func collectProcesses(snap *pb.RptAssetSnapshot) {
	procs, err := listProcessReaders()
	if err != nil {
		collectionStatus(snap, "processes", pb.AssetCollection_FAILED, "enumeration_failed")
		return
	}
	var permDenied, fieldFailed bool
	recordErr := func(err error) {
		if isPermissionError(err) {
			permDenied = true
		} else {
			fieldFailed = true
		}
	}
	for _, p := range procs {
		pid := p.PID()
		kernelPseudo := isWindowsKernelPseudoProcess(pid)

		name, nameErr := p.Name()
		if nameErr != nil {
			if isProcessGoneError(nameErr) {
				continue
			}
			recordErr(nameErr)
		} else if strings.TrimSpace(name) == "" {
			fieldFailed = true
		}

		args, cmdErr := p.CmdlineSlice()
		if cmdErr != nil {
			if !kernelPseudo && isProcessGoneError(cmdErr) {
				continue
			}
			if !kernelPseudo {
				recordErr(cmdErr)
			}
		}

		var rss uint64
		mem, memErr := p.MemoryInfo()
		if memErr != nil {
			if !kernelPseudo && isProcessGoneError(memErr) {
				continue
			}
			if !kernelPseudo {
				recordErr(memErr)
			}
		} else if mem != nil {
			rss = mem.RSS
		}

		username, userErr := p.Username()
		if userErr != nil {
			if !kernelPseudo && isProcessGoneError(userErr) {
				continue
			}
			var unknownUID user.UnknownUserIdError
			if errors.As(userErr, &unknownUID) {
				// Valid unmapped Linux/container UID; preserve numeric identity cleanly.
				username = "uid:" + strconv.Itoa(int(unknownUID))
			} else if !kernelPseudo {
				recordErr(userErr)
			}
		}

		exe, exeErr := p.Exe()
		if exeErr != nil {
			if isProcessGoneError(exeErr) {
				if !kernelPseudo {
					// Linux kernel threads and zombies lack /proc/<pid>/exe (ENOENT)
					// while stat/status remain readable with empty args and zero RSS.
					isKernelOrZombie := (errors.Is(exeErr, os.ErrNotExist) || errors.Is(exeErr, syscall.ENOENT)) &&
						nameErr == nil && memErr == nil && len(args) == 0 && rss == 0
					if !isKernelOrZombie {
						continue
					}
					exe = ""
				}
			} else if !kernelPseudo {
				recordErr(exeErr)
			}
		}

		snap.Processes = append(snap.Processes, &pb.ProcessInfo{
			Pid:      pid,
			Name:     name,
			Exe:      exe,
			Cmdline:  redactCommandLine(args),
			User:     username,
			RssBytes: rss,
		})
	}
	switch {
	case permDenied:
		collectionStatus(snap, "processes", pb.AssetCollection_PARTIAL, "process_fields_permission_denied")
	case fieldFailed:
		collectionStatus(snap, "processes", pb.AssetCollection_PARTIAL, "process_fields_incomplete")
	}
}

func redactCommandLine(args []string) string {
	redacted := append([]string(nil), args...)
	for i, arg := range redacted {
		lower := strings.ToLower(arg)
		if sensitiveArgumentKey(lower) != "" {
			if equals := strings.Index(arg, "="); equals >= 0 {
				redacted[i] = arg[:equals+1] + "***"
			} else if i+1 < len(redacted) {
				redacted[i+1] = "***"
			}
		}
	}
	return strings.Join(redacted, " ")
}

func sensitiveArgumentKey(arg string) string {
	name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
	name = strings.ReplaceAll(name, "_", "-")
	for _, key := range []string{
		"password", "passwd", "pwd", "token", "secret", "api-key", "apikey",
		"access-key", "accesskey", "client-secret", "clientsecret", "private-key", "privatekey",
		"auth", "authorization", "bearer", "cookie",
	} {
		if name == key || strings.HasSuffix(name, "-"+key) {
			return key
		}
	}
	return ""
}

/* ==================== 磁盘（gopsutil 跨平台） ==================== */

// collectDisks 采集物理文件系统容量（Linux 过滤 /proc /sys 等虚拟挂载）
func collectDisks(snap *pb.RptAssetSnapshot) {
	parts, err := listPartitions(false) // false = 仅物理文件系统
	if err != nil {
		collectionStatus(snap, "disks", pb.AssetCollection_FAILED, "enumeration_failed")
		return
	}
	seen := make(map[string]bool, len(parts))
	var unreadable, invalidUsage bool
	for _, p := range parts {
		if strings.TrimSpace(p.Mountpoint) == "" || strings.ContainsRune(p.Mountpoint, '\x00') || len(p.Mountpoint) > 1024 ||
			strings.ContainsRune(p.Fstype, '\x00') || len(p.Fstype) > 128 {
			invalidUsage = true
			continue
		}
		if seen[p.Mountpoint] {
			continue
		}
		u, err := diskUsage(p.Mountpoint)
		if err != nil || u == nil || u.Total == 0 {
			unreadable = true
			continue
		}
		if u.Used > u.Total {
			invalidUsage = true
			continue
		}
		seen[p.Mountpoint] = true
		snap.Disks = append(snap.Disks, &pb.DiskInfo{
			Mount:      p.Mountpoint,
			FsType:     p.Fstype,
			TotalBytes: u.Total,
			UsedBytes:  u.Used,
		})
	}
	switch {
	case invalidUsage:
		collectionStatus(snap, "disks", pb.AssetCollection_PARTIAL, "invalid_mount_usage")
	case unreadable:
		collectionStatus(snap, "disks", pb.AssetCollection_PARTIAL, "mount_unreadable")
	}
}

var listConnections = gnet.Connections
var listProcesses = process.Processes
var listPartitions = disk.Partitions
var diskUsage = disk.Usage

func collectionStatus(snap *pb.RptAssetSnapshot, category string, status pb.AssetCollection_Status, reason string) {
	if len(reason) > 128 {
		reason = reason[:128]
	}
	for _, c := range snap.Collections {
		if c.Category == category {
			c.Status = status
			c.Error = reason
			c.CollectedAt = time.Now().UnixMilli()
			return
		}
	}
	snap.Collections = append(snap.Collections, &pb.AssetCollection{Category: category, Status: status, Error: reason, CollectedAt: time.Now().UnixMilli()})
}
