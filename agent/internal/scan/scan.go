// Package scan 安全扫描引擎（docs/04 §4）：
//   - 弱口令检测：本机离线验证（shadow 哈希比对），绝不做在线爆破
//   - 端口服务识别：本地监听表 + 进程映射 + 内置指纹/高危端口表，被动识别
//   - 漏洞比对：M2 由服务端完成（t_cve_db × t_asset_software 快照），Agent 不持有 CVE 库
package scan

import (
	"log/slog"
	"strconv"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// Run 执行扫描：includeWeakPwd / includePortService 由指令参数决定
func Run(taskID string, includeWeakPwd, includePortService bool, log *slog.Logger) *pb.RptScanResult {
	result := &pb.RptScanResult{TaskId: taskID}
	if includeWeakPwd {
		start := time.Now()
		result.WeakPasswords = detectWeakPasswords(log)
		log.Info("弱口令检测完成", "findings", len(result.GetWeakPasswords()),
			"duration", time.Since(start).Round(time.Millisecond))
	}
	if includePortService {
		start := time.Now()
		result.PortServices = detectPortServices(log)
		risky := 0
		for _, p := range result.GetPortServices() {
			if p.GetRisky() {
				risky++
			}
		}
		log.Info("端口服务识别完成", "ports", len(result.GetPortServices()), "risky", risky,
			"duration", time.Since(start).Round(time.Millisecond))
	}
	return result
}

/* ==================== 端口服务识别（被动） ==================== */

// riskyPorts 高危端口清单（docs/04 §4.3：Windows RPC/SMB 与常见远控）
var riskyPorts = map[uint32]string{
	135: "Windows RPC 端点映射（蠕虫/勒索常用入口）",
	137: "NetBIOS 名称服务（信息泄露）",
	138: "NetBIOS 数据报服务（信息泄露）",
	139: "NetBIOS 会话服务（SMB，历史漏洞密集）",
	445: "SMB 直连（EternalBlue/WannaCry 传播途径）",
	593: "RPC over HTTP（暴露面）",
	1025: "RPC 动态端口（远控常用）",
	3127: "MyDoom 后门端口",
	4444: "Metasploit 默认反向 Shell 端口",
	5900: "VNC 远程桌面（弱口令高发）",
	6379: "Redis 未授权访问高发端口",
	11211: "Memcached 未授权访问（UDP 反射放大）",
	27017: "MongoDB 未授权访问高发端口",
}

// fingerprints 常见服务指纹（端口 → 服务名），进程名仅作旁证
var fingerprints = map[uint32]string{
	22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	111: "rpcbind", 123: "ntp", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 500: "isakmp", 514: "syslog", 587: "smtp", 636: "ldaps", 873: "rsync",
	993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
	2049: "nfs", 2181: "zookeeper", 2375: "docker-api", 2376: "docker-api-tls",
	3306: "mysql", 3389: "rdp", 4444: "unknown-backdoor", 5432: "postgresql",
	5601: "kibana", 5900: "vnc", 5984: "couchdb", 6379: "redis", 8080: "http-alt",
	8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb", 27018: "mongodb",
}

// detectPortServices 监听端口 → 服务指纹 + 高危标记（与 collector 端口采集同源，被动识别）
func detectPortServices(log *slog.Logger) []*pb.PortServiceFinding {
	conns, err := net.Connections("inet")
	if err != nil {
		log.Error("端口识别失败", "err", err)
		return nil
	}
	seen := map[string]bool{} // "proto:port:proc" 去重
	nameCache := map[int32]string{}
	var findings []*pb.PortServiceFinding
	for _, c := range conns {
		isUDP := c.Type == syscall.SOCK_DGRAM
		if !isUDP && c.Status != "LISTEN" {
			continue
		}
		proto := "tcp"
		if isUDP {
			proto = "udp"
		}
		port := uint32(c.Laddr.Port)
		if port == 0 {
			continue
		}
		proc := procName(c.Pid, nameCache)
		key := proto + ":" + strconv.FormatUint(uint64(port), 10) + ":" + proc
		if seen[key] {
			continue
		}
		seen[key] = true

		risky, reason := false, ""
		if r, ok := riskyPorts[port]; ok {
			risky, reason = true, r
		}
		findings = append(findings, &pb.PortServiceFinding{
			Port:        port,
			Protocol:    proto,
			Process:     proc,
			Service:     fingerprints[port],
			Risky:       risky,
			RiskyReason: reason,
		})
	}
	return findings
}

// procName pid → 进程名（带缓存）
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
