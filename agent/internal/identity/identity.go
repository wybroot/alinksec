// Package identity 采集主机身份与运行指标（跨平台：Linux / Windows）
package identity

import (
	"fmt"
	"math/rand/v2"
	"net"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// AgentVersion 当前 Agent 版本（升级任务比对依据）
const AgentVersion = "0.0.2"

// HostInfo 采集主机静态信息（注册时上报，内容与 proto HostInfo 对齐）
func HostInfo() *pb.HostInfo {
	hi, err := host.Info()
	if err != nil {
		hi = &host.InfoStat{}
	}
	osType := pb.OsType_OS_LINUX
	if runtime.GOOS == "windows" {
		osType = pb.OsType_OS_WINDOWS
	}
	ips, macs := netAddrs()
	return &pb.HostInfo{
		Hostname:     hi.Hostname,
		OsType:       osType,
		OsVersion:    hi.Platform + " " + hi.PlatformVersion,
		Kernel:       hi.KernelVersion,
		Arch:         runtime.GOARCH,
		AgentVersion: AgentVersion,
		IpList:       ips,
		MacList:      macs,
		MachineId:    hi.HostID, // Linux: /etc/machine-id；Windows: MachineGuid（gopsutil 跨平台实现）
	}
}

// HeartbeatSample 心跳概要指标
type HeartbeatSample struct {
	CpuUsage     float32
	MemUsage     float32
	ProcessCount uint32
	UptimeSec    int64
}

// Sample 采集一次概要指标（非阻塞 CPU 采样：与上一次调用期间的均值）
func Sample() HeartbeatSample {
	s := HeartbeatSample{}
	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		s.CpuUsage = float32(pct[0])
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		s.MemUsage = float32(vm.UsedPercent)
	}
	if pids, err := process.Pids(); err == nil {
		s.ProcessCount = uint32(len(pids))
	}
	if h, err := host.Info(); err == nil {
		s.UptimeSec = int64(h.Uptime)
	}
	return s
}

// netAddrs 收集非回环网卡 IP 与 MAC
func netAddrs() (ips, macs []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if ifc.HardwareAddr != nil && len(ifc.HardwareAddr.String()) > 0 {
			macs = append(macs, ifc.HardwareAddr.String())
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				ips = append(ips, ipn.IP.String())
			}
		}
	}
	return
}

// Nonce 生成注册防重放随机数（毫秒时间戳 + 随机后缀足够 M1 使用）
func Nonce() string {
	return fmt.Sprintf("%d-%08x", time.Now().UnixNano(), rand.Uint32())
}
