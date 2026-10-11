//go:build linux

package collector

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/alinksec/alinksec-agent/internal/packageversion"
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
		"--qf", "%{NAME}\x1f%{EPOCHNUM}\x1f%{VERSION}\x1f%{RELEASE}\x1f%{VENDOR}\x1f%{INSTALLTIME}\n").Output()
	if err != nil {
		return nil
	}
	return parseRPMPackages(string(out))
}

func parseRPMPackages(out string) []*pb.SoftwareInfo {
	var list []*pb.SoftwareInfo
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		if len(f) != 6 || f[0] == "" {
			continue
		}
		version, err := packageversion.RPM(f[1], f[2], f[3])
		if err != nil {
			continue
		}
		ts, _ := strconv.ParseInt(f[5], 10, 64)
		if ts < 0 || ts > (1<<63-1)/1000 {
			ts = 0
		}
		list = append(list, &pb.SoftwareInfo{
			Name:        f[0],
			Version:     version,
			Vendor:      f[4],
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
