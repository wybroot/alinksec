//go:build linux

package guard

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	containerIDRegex = regexp.MustCompile(`(?i)(?:docker-|docker/|cri-containerd-|containerd/|crio-|libpod-|podman-)([0-9a-fA-F]{12,64})`)
	kubepodsRegex    = regexp.MustCompile(`(?i)kubepods.*?(?:docker-|containerd-|crio-)?([0-9a-fA-F]{12,64})`)
)

// inspectProcessContainer reads /proc/<pid>/cgroup on Linux to identify container isolation
func inspectProcessContainer(pid int32) (bool, string) {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return false, ""
	}
	return parseCgroupContent(string(data))
}

// parseCgroupContent parses cgroup records to identify container presence and container ID
func parseCgroupContent(content string) (bool, string) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := containerIDRegex.FindStringSubmatch(line); len(m) > 1 {
			id := m[1]
			if len(id) > 12 {
				id = id[:12]
			}
			return true, id
		}
		if m := kubepodsRegex.FindStringSubmatch(line); len(m) > 1 {
			id := m[1]
			if len(id) > 12 {
				id = id[:12]
			}
			return true, id
		}
		if strings.Contains(line, "/docker/") || strings.Contains(line, "/lxc/") || strings.Contains(line, "/kubepods/") {
			parts := strings.Split(line, "/")
			if len(parts) > 1 {
				last := parts[len(parts)-1]
				last = strings.TrimSuffix(last, ".scope")
				if len(last) > 12 {
					last = last[:12]
				}
				return true, last
			}
			return true, "container"
		}
	}
	return false, ""
}

// isNetworkNamespaceIsolated checks if the target PID has a different network namespace
func isNetworkNamespaceIsolated(pid int32) bool {
	selfNetNs, errSelf := os.Readlink("/proc/self/ns/net")
	procNetNs, errProc := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if errSelf == nil && errProc == nil && selfNetNs != "" && procNetNs != "" {
		return selfNetNs != procNetNs
	}
	return false
}

// inspectProcessNetwork reads network sockets for the process and detects netns isolation
func inspectProcessNetwork(pid int32) (string, []procNetConn) {
	if isNetworkNamespaceIsolated(pid) {
		return "unavailable", nil
	}

	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return "unavailable", nil
	}

	socketInodes := make(map[string]struct{})
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if inode != "" {
				socketInodes[inode] = struct{}{}
			}
		}
	}

	if len(socketInodes) == 0 {
		return "available", []procNetConn{}
	}

	var conns []procNetConn
	for _, protoPath := range []struct {
		family string
		path   string
	}{
		{"tcp", fmt.Sprintf("/proc/%d/net/tcp", pid)},
		{"tcp6", fmt.Sprintf("/proc/%d/net/tcp6", pid)},
	} {
		if data, err := os.ReadFile(protoPath.path); err == nil {
			parsed := parseProcNetTCPContent(string(data), protoPath.family, socketInodes)
			conns = append(conns, parsed...)
			if len(conns) >= 16 {
				conns = conns[:16]
				break
			}
		}
	}

	return "available", conns
}

// parseProcNetTCPContent parses /proc/net/tcp or /proc/net/tcp6 formatted text
func parseProcNetTCPContent(content, family string, inodes map[string]struct{}) []procNetConn {
	var conns []procNetConn
	scanner := bufio.NewScanner(strings.NewReader(content))
	// Skip header line
	if !scanner.Scan() {
		return conns
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		inode := fields[9]
		if _, ok := inodes[inode]; !ok {
			continue
		}

		local := parseHexAddr(fields[1], family)
		remote := parseHexAddr(fields[2], family)
		state := parseTCPState(fields[3])

		conns = append(conns, procNetConn{
			Family: family,
			Local:  local,
			Remote: remote,
			State:  state,
		})
		if len(conns) >= 16 {
			break
		}
	}
	return conns
}

func parseHexAddr(hexAddr, family string) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return hexAddr
	}
	portInt, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		portInt = 0
	}

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return fmt.Sprintf("%s:%d", parts[0], portInt)
	}

	if family == "tcp" && len(ipBytes) == 4 {
		// IPv4 in /proc/net/tcp is little-endian
		ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
		return fmt.Sprintf("%s:%d", ip.String(), portInt)
	} else if family == "tcp6" && len(ipBytes) == 16 {
		var ip net.IP = make([]byte, 16)
		for i := 0; i < 16; i += 4 {
			ip[i] = ipBytes[i+3]
			ip[i+1] = ipBytes[i+2]
			ip[i+2] = ipBytes[i+1]
			ip[i+3] = ipBytes[i]
		}
		return fmt.Sprintf("[%s]:%d", ip.String(), portInt)
	}
	return fmt.Sprintf("%s:%d", parts[0], portInt)
}

func parseTCPState(hexState string) string {
	switch hexState {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	default:
		return hexState
	}
}
