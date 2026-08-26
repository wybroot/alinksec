//go:build linux

package collector

import (
	"os/exec"
	"strconv"
	"strings"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// collectSoftware Linux 软件清单：优先 rpm（RHEL 系），回退 dpkg（Debian 系）。
// 分隔符用 \x1f，规避厂商名含空白导致的列错位。
func collectSoftware(snap *pb.RptAssetSnapshot) {
	if sw := rpmPackages(); len(sw) > 0 {
		snap.Software = sw
		return
	}
	snap.Software = dpkgPackages()
}

// rpmPackages rpm -qa；INSTALLTIME 为 epoch 秒
func rpmPackages() []*pb.SoftwareInfo {
	out, err := exec.Command("rpm", "-qa",
		"--qf", "%{NAME}\x1f%{VERSION}-%{RELEASE}\x1f%{VENDOR}\x1f%{INSTALLTIME}\n").Output()
	if err != nil {
		return nil
	}
	var list []*pb.SoftwareInfo
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		ts, _ := strconv.ParseInt(f[3], 10, 64)
		list = append(list, &pb.SoftwareInfo{
			Name:        f[0],
			Version:     f[1],
			Vendor:      f[2],
			InstallTime: ts * 1000,
			Source:      "rpm",
		})
	}
	return list
}

// dpkgPackages dpkg-query -W（全量已安装包；dpkg 无安装时间与厂商字段，留空）
func dpkgPackages() []*pb.SoftwareInfo {
	out, err := exec.Command("dpkg-query", "-W",
		"-f", "${Package}\x1f${Version}\x1f${db:Status-Abbrev}\n").Output()
	if err != nil {
		return nil
	}
	var list []*pb.SoftwareInfo
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\x1f")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		// db:Status-Abbrev 形如 "ii "，仅保留已正确安装的包（第二位 i）
		if !strings.HasPrefix(f[2], "ii") {
			continue
		}
		list = append(list, &pb.SoftwareInfo{
			Name:    f[0],
			Version: f[1],
			Source:  "dpkg",
		})
	}
	return list
}
