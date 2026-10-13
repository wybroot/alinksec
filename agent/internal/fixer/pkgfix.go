// Package fixer 软件包类修复（docs/05 §3.3）：
// 前置检查（磁盘空间）→ 下载补丁（sha256 校验）→ 包管理器安装 → 版本复核。
// 与配置类不同：**不自动回滚**（降级风险大于收益）；rpm 记录旧版本号供人工降级参考。
package fixer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/alinksec/alinksec-agent/internal/packageversion"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securehttp"
)

// minFreeDiskMB 安装前置磁盘余量（docs/05：前置检查磁盘空间）
const minFreeDiskMB = 500

// downloadTimeoutMSU/补丁下载整体超时（内网带宽有限，给足）
const downloadTimeout = 30 * time.Minute

// PkgPayload CmdVulnFix PACKAGE 项 payload（FixTaskService 构造）
type PkgPayload struct {
	RepoType      string              `json:"repo_type"`      // rpm / deb
	PkgName       string              `json:"pkg_name"`       // openssl / KB5034441
	TargetVersion string              `json:"target_version"` // 1.1.1k-26.el7_9
	DownloadURL   string              `json:"download_url"`   // 平台补丁下载端点
	Sha256        string              `json:"sha256"`
	CveID         string              `json:"cve_id"`     // 关联 CVE（上报展示）
	FindingID     string              `json:"finding_id"` // t_vuln_finding.id（平台回写状态用）
	Inventory     PackageInstallation `json:"inventory"`
}

// Contract 1 pins the approved installation; legacy commands cannot silently create a new package.
type PackageInstallation struct {
	Contract         int    `json:"contract"`
	Source           string `json:"source"`
	Architecture     string `json:"architecture"`
	DistroID         string `json:"distro_id"`
	DistroVersion    string `json:"distro_version"`
	InstalledVersion string `json:"installed_version"`
	OSType           int    `json:"os_type"`
	OSVersion        string `json:"os_version"`
}

type packageMetadata struct{ Name, Version, Architecture, Source string }
type packageOperations struct {
	disk     func() (float64, error)
	identity func(string) (PackageInstallation, error)
	download func(string, *PkgPayload) (string, error)
	metadata func(*PkgPayload, string) (packageMetadata, error)
	install  func(*PkgPayload, string, func(string, ...any)) (bool, error)
}

var repairName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.-]{0,254}$`)
var repairVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+:~_^-]{0,254}$`)
var repairArchitecture = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$`)
var repairDistro = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
var repairDistroVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var repairChecksum = regexp.MustCompile(`^[a-f0-9]{64}$`)

// fixPackage 软件包类修复单项
func fixPackage(f *pb.FixItem, workDir string, log *slog.Logger) *pb.FixResultItem {
	return fixPackageWithOperations(f, workDir, log, packageOperations{disk: freeDiskMB,
		identity: func(name string) (PackageInstallation, error) { return currentInstallation(name, log) },
		download: downloadPatch, metadata: inspectPackage, install: installPatch})
}

func fixPackageWithOperations(f *pb.FixItem, workDir string, log *slog.Logger, ops packageOperations) *pb.FixResultItem {
	item := &pb.FixResultItem{RefId: f.GetRefId()}
	var lines []string
	addLog := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

	p, err := parsePkgPayload(f.GetPayload())
	if err != nil {
		item.Success, item.Log = false, err.Error()
		return item
	}
	if p.FindingID == "" || p.FindingID != f.GetRefId() {
		item.Log = "修复记录与审批的软件包目标不一致，未执行修复"
		return item
	}
	addLog("软件包修复: %s → %s (%s) 关联 %s", p.PkgName, p.TargetVersion, p.RepoType, p.CveID)

	// Query the current native installation before downloading anything.
	current, err := ops.identity(p.PkgName)
	if err != nil || !sameInstallation(p, current, p.Inventory.InstalledVersion) {
		item.Log = "当前安装身份缺失、采集失败或已变化，未执行修复，请重新采集并审批"
		return item
	}
	if free, err := ops.disk(); err != nil || free < minFreeDiskMB {
		item.Success, item.Log = false,
			fmt.Sprintf("磁盘余量不足（%.0fMB < %dMB），已中止（未做任何变更）", free, minFreeDiskMB)
		return item
	}

	// 2. 下载补丁 + sha256 校验
	tmp, err := ops.download(workDir, p)
	if err != nil {
		addLog("补丁下载/校验失败，未执行安装；请检查连接、证书和包摘要")
		item.Success, item.Log = false, joinLog(lines)
		return item
	}
	defer os.Remove(tmp)
	addLog("补丁下载并校验通过: %s", filepath.Base(tmp))

	metadata, err := ops.metadata(p, tmp)
	if err != nil || metadata.Name != p.PkgName || metadata.Source != p.Inventory.Source || metadata.Architecture != p.Inventory.Architecture || !packageVersionMatches(p.RepoType, metadata.Version, p.TargetVersion) {
		addLog("补丁内部包名、完整版本、来源或包架构不匹配，或无法在限制内解析；未执行安装")
		item.Log = joinLog(lines)
		return item
	}
	// A download may outlive the approved installation. Recheck immediately before installation.
	current, err = ops.identity(p.PkgName)
	if err != nil || !sameInstallation(p, current, p.Inventory.InstalledVersion) {
		addLog("下载后当前安装身份已变化或无法核对，未执行安装")
		item.Log = joinLog(lines)
		return item
	}
	addLog("安装前身份与二进制元数据复核通过；原版本: %s", current.InstalledVersion)

	// 4. 安装（平台实现；失败不回滚，如实上报）
	reboot, err := ops.install(p, tmp, func(format string, args ...any) { addLog(format, args...) })
	item.RebootRequired = reboot
	if err != nil {
		addLog("安装失败: %v（不自动回滚，请人工检查依赖/窗口后重试）", err)
		item.Success, item.Log = false, joinLog(lines)
		log.Warn("软件包修复失败", "pkg", p.PkgName, "err", err)
		return item
	}

	current, err = ops.identity(p.PkgName)
	if err != nil || !sameInstallation(p, current, p.TargetVersion) {
		addLog("安装后未确认同一发行版、来源、包架构和目标完整版本；需人工检查，不标记已修复")
		item.Log = joinLog(lines)
		return item
	}
	item.Verified = true
	addLog("安装后身份与完整版本复核通过: %s", current.InstalledVersion)

	item.Success, item.Log = true, joinLog(lines)
	log.Info("软件包修复完成", "pkg", p.PkgName, "version", p.TargetVersion, "reboot", reboot)
	return item
}

func sameInstallation(p *PkgPayload, current PackageInstallation, version string) bool {
	expected := p.Inventory
	return current.Contract == 1 && current.OSType == 1 && current.Source == expected.Source && current.Architecture == expected.Architecture && current.DistroID == expected.DistroID && current.DistroVersion == expected.DistroVersion && packageVersionMatches(p.RepoType, current.InstalledVersion, version)
}

func packageVersionMatches(repoType, actual, target string) bool {
	if repoType != "rpm" {
		return actual == target
	}
	a, errA := packageversion.RPMIdentity(actual)
	b, errB := packageversion.RPMIdentity(target)
	return errA == nil && errB == nil && a == b
}

func parsePkgPayload(payload string) (*PkgPayload, error) {
	if payload == "" {
		return nil, fmt.Errorf("payload 为空")
	}
	var p PkgPayload
	if err := jsonUnmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("payload 解析失败: %w", err)
	}
	if p.PkgName == "" || p.TargetVersion == "" || p.DownloadURL == "" || p.Sha256 == "" {
		return nil, fmt.Errorf("payload 缺少 pkg_name/target_version/download_url")
	}
	switch p.RepoType {
	case "rpm", "deb":
	default:
		return nil, fmt.Errorf("不支持的补丁类型: %s", p.RepoType)
	}
	source := "rpm"
	if p.RepoType == "deb" {
		source = "dpkg"
	}
	identity := p.Inventory
	if identity.Contract != 1 || identity.OSType != 1 || identity.Source != source || !repairName.MatchString(p.PkgName) || !repairVersion.MatchString(p.TargetVersion) || !repairVersion.MatchString(identity.InstalledVersion) || !repairArchitecture.MatchString(identity.Architecture) || !repairDistro.MatchString(identity.DistroID) || !repairDistroVersion.MatchString(identity.DistroVersion) || !repairChecksum.MatchString(p.Sha256) {
		return nil, fmt.Errorf("软件包修复缺少受支持的执行契约、完整安装身份或有效摘要，请更新 Agent 并重新采集审批")
	}
	if p.RepoType == "rpm" && (!packageVersionMatches("rpm", p.TargetVersion, p.TargetVersion) || !packageVersionMatches("rpm", identity.InstalledVersion, identity.InstalledVersion)) {
		return nil, fmt.Errorf("RPM 修复必须声明完整 epoch/version/release")
	}
	if strings.ContainsAny(p.DownloadURL, "\r\n") {
		return nil, fmt.Errorf("下载地址非法")
	}
	return &p, nil
}

// downloadPatch 下载补丁到临时文件并校验 sha256（原子：校验失败即删）
func downloadPatch(workDir string, p *PkgPayload) (string, error) {
	resp, err := securehttp.Get(context.Background(), workDir, p.DownloadURL, downloadTimeout)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("下载返回 %s", resp.Status)
	}
	tmp, err := os.CreateTemp("", "alinksec-patch-*."+p.RepoType)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if p.Sha256 != "" && !stringsEqualFold(hex.EncodeToString(h.Sum(nil)), p.Sha256) {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("sha256 校验失败（包损坏或被篡改）")
	}
	return tmp.Name(), nil
}

func joinLog(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
