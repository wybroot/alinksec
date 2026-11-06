//go:build linux

package fixer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/alinksec/alinksec-agent/internal/packageversion"
	"github.com/shirou/gopsutil/v3/disk"
)

// freeDiskMB 系统临时目录所在盘余量
func freeDiskMB() (float64, error) {
	u, err := disk.Usage(os.TempDir())
	if err != nil {
		return 0, err
	}
	return float64(u.Free) / (1 << 20), nil
}

// queryPkgVersion 查询已安装版本（rpm 优先，回退 dpkg；未安装返回空）
func queryPkgVersion(pkg string) string {
	if _, err := exec.LookPath("rpm"); err == nil {
		if out, err := exec.Command("rpm", "-q", "--qf", "%{EPOCHNUM}\x1f%{VERSION}\x1f%{RELEASE}\n", "--", pkg).Output(); err == nil {
			return rpmInstalledVersion(string(out))
		}
		return ""
	}
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f", "${Version}", pkg).Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func rpmInstalledVersion(out string) string {
	out = strings.TrimSuffix(out, "\n")
	fields := strings.Split(out, "\x1f")
	if len(fields) != 3 || strings.ContainsAny(out, "\r\n") {
		return ""
	}
	version, err := packageversion.RPM(fields[0], fields[1], fields[2])
	if err != nil {
		return ""
	}
	return version
}

// installPatch Linux 安装：单包文件直装（依赖走客户现有源，不污染 repo 配置）：
// rpm: yum/dnf install -y ./file.rpm；deb: apt-get install -y ./file.deb（自动解依赖）
func installPatch(p *PkgPayload, tmpFile string, addLog func(string, ...any)) (reboot bool, err error) {
	pkgNameLower := strings.ToLower(p.PkgName)
	isCorePackage := strings.Contains(pkgNameLower, "kernel") ||
		strings.Contains(pkgNameLower, "linux-image") ||
		strings.Contains(pkgNameLower, "glibc") ||
		strings.Contains(pkgNameLower, "libc6") ||
		strings.Contains(pkgNameLower, "systemd")

	switch p.RepoType {
	case "rpm":
		installer := "yum"
		if _, e := exec.LookPath("dnf"); e == nil {
			installer = "dnf"
		}
		addLog("执行: %s install -y %s", installer, filepathBase(tmpFile))
		out, e := packageCommand(false, 15*time.Minute, installer, "install", "-y", tmpFile)
		if e != nil {
			return false, fmt.Errorf("%s: %s", e, tailOutput(out))
		}
		reboot = isCorePackage
		if !reboot {
			if _, e := os.Stat("/run/reboot-required"); e == nil {
				reboot = true
			} else if needsRestartCmd, err := exec.LookPath("needs-restarting"); err == nil {
				if rOut, _ := exec.Command(needsRestartCmd, "-r").Output(); len(rOut) > 0 {
					reboot = strings.Contains(string(rOut), "Reboot is required")
				}
			}
		}
		if reboot {
			addLog("核心系统组件更新或存在重启标志，需重启生效")
		}
		return reboot, nil
	case "deb":
		addLog("执行: apt-get install -y %s", filepathBase(tmpFile))
		out, e := packageCommand(false, 15*time.Minute, "apt-get", "install", "-y", tmpFile)
		if e != nil {
			return false, fmt.Errorf("apt-get: %s", tailOutput(out))
		}
		reboot = isCorePackage
		if !reboot {
			if _, e := os.Stat("/var/run/reboot-required"); e == nil {
				reboot = true
			}
		}
		if reboot {
			addLog("核心系统组件更新或存在重启标志，需重启生效")
		}
		return reboot, nil
	default:
		return false, fmt.Errorf("Linux 不支持补丁类型 %s", p.RepoType)
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func tailOutput(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 400 {
		s = "..." + s[len(s)-400:]
	}
	return s
}

// stringsEqualFold 十六进制哈希大小写不敏感比对
func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// jsonUnmarshal encoding/json 包装（避免 pkgfix.go 重复 import）
func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
