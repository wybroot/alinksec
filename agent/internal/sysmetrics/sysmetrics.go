// Package sysmetrics 主机指标采集（docs/03 §3.1 指标命名，前缀 alinksec_）。
// 快组 10s：CPU/load/内存/磁盘IO/网卡/进程数；慢组 60s：内存总量/磁盘容量。
// agent_id 与 hostname 标签由服务端出口补齐（转发时统一注入）。
package sysmetrics

import (
	"log/slog"
	"runtime"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// CollectFast 快组（10s 周期）：CPU 使用率/load/已用内存/swap/磁盘IO累计/网卡流量累计/进程数。
// cpu.Percent(0) 基于上次调用差值计算，适合固定 ticker 周期调用。
func CollectFast(log *slog.Logger) []*pb.MetricSample {
	ts := time.Now().UnixMilli()
	var out []*pb.MetricSample
	add := func(name string, value float64, labels map[string]string) {
		out = append(out, &pb.MetricSample{Name: name, Labels: labels, Value: value, Ts: ts})
	}

	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		add("alinksec_cpu_usage", pct[0], nil)
	} else if err != nil {
		log.Debug("cpu 采集失败", "err", err)
	}

	if runtime.GOOS != "windows" { // Windows 无 loadavg
		if avg, err := load.Avg(); err == nil {
			add("alinksec_cpu_load1", avg.Load1, nil)
			add("alinksec_cpu_load5", avg.Load5, nil)
			add("alinksec_cpu_load15", avg.Load15, nil)
		}
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		add("alinksec_mem_used_bytes", float64(vm.Used), nil)
	}
	if sw, err := mem.SwapMemory(); err == nil {
		add("alinksec_swap_used_bytes", float64(sw.Used), nil)
	}

	if io, err := disk.IOCounters(); err == nil {
		for dev, c := range io {
			if skipDevice(dev) {
				continue
			}
			add("alinksec_disk_read_bytes_total", float64(c.ReadBytes), map[string]string{"device": dev})
			add("alinksec_disk_write_bytes_total", float64(c.WriteBytes), map[string]string{"device": dev})
		}
	}

	if ifaces, err := net.IOCounters(true); err == nil {
		for _, n := range ifaces {
			if skipIface(n.Name) {
				continue
			}
			add("alinksec_net_rx_bytes_total", float64(n.BytesRecv), map[string]string{"iface": n.Name})
			add("alinksec_net_tx_bytes_total", float64(n.BytesSent), map[string]string{"iface": n.Name})
		}
	}

	if pids, err := process.Pids(); err == nil {
		add("alinksec_process_count", float64(len(pids)), nil)
	}
	return out
}

// CollectSlow 慢组（60s 周期）：内存总量/各挂载点磁盘容量（过滤虚拟文件系统）。
func CollectSlow(log *slog.Logger) []*pb.MetricSample {
	ts := time.Now().UnixMilli()
	var out []*pb.MetricSample
	add := func(name string, value float64, labels map[string]string) {
		out = append(out, &pb.MetricSample{Name: name, Labels: labels, Value: value, Ts: ts})
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		add("alinksec_mem_total_bytes", float64(vm.Total), nil)
	}

	if parts, err := disk.Partitions(false); err == nil {
		for _, p := range parts {
			if skipMount(p.Mountpoint, p.Fstype) {
				continue
			}
			u, err := disk.Usage(p.Mountpoint)
			if err != nil {
				continue
			}
			add("alinksec_disk_used_bytes", float64(u.Used), map[string]string{"mount": p.Mountpoint})
			add("alinksec_disk_total_bytes", float64(u.Total), map[string]string{"mount": p.Mountpoint})
		}
	}
	return out
}

/* ---------- 基数过滤（docs/03 §3.1：过滤虚拟网卡与 tmpfs） ---------- */

var skipIfacePrefixes = []string{"lo", "veth", "docker", "br-", "vEthernet", "isatap", "vmkube"}

func skipIface(name string) bool {
	for _, p := range skipIfacePrefixes {
		if len(name) >= len(p) && name[:len(p)] == p {
			return true
		}
	}
	return name == ""
}

var skipFstypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "devfs": true, "overlay": true, "squashfs": true,
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "ramfs": true,
	"efivarfs": true, "fuse.*": true, "autofs": true, "mqueue": true, "hugetlbfs": true,
	"nsfs": true, "tracefs": true, "debugfs": true, "configfs": true, "pstore": true,
	"bpf": true, "binfmt_misc": true, "rpc_pipefs": true,
}

func skipMount(mount, fstype string) bool {
	if skipFstypes[fstype] {
		return true
	}
	return mount == "" || mount == "/boot/efi" || mount == "/boot/grub2"
}

// skipDevice 磁盘 IO 计数过滤：跳过 loop/ram 设备
func skipDevice(dev string) bool {
	return len(dev) >= 4 && (dev[:4] == "loop" || dev[:3] == "ram")
}
