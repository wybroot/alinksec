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
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securehttp"
)

// minFreeDiskMB 安装前置磁盘余量（docs/05：前置检查磁盘空间）
const minFreeDiskMB = 500

// downloadTimeoutMSU/补丁下载整体超时（内网带宽有限，给足）
const downloadTimeout = 30 * time.Minute

// PkgPayload CmdVulnFix PACKAGE 项 payload（FixTaskService 构造）
type PkgPayload struct {
	RepoType      string `json:"repo_type"`      // rpm / deb / msu
	PkgName       string `json:"pkg_name"`       // openssl / KB5034441
	TargetVersion string `json:"target_version"` // 1.1.1k-26.el7_9
	DownloadURL   string `json:"download_url"`   // 平台补丁下载端点
	Sha256        string `json:"sha256"`
	CveID         string `json:"cve_id"`     // 关联 CVE（上报展示）
	FindingID     string `json:"finding_id"` // t_vuln_finding.id（平台回写状态用）
}

// fixPackage 软件包类修复单项
func fixPackage(f *pb.FixItem, workDir string, log *slog.Logger) *pb.FixResultItem {
	item := &pb.FixResultItem{RefId: f.GetRefId()}
	var lines []string
	addLog := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

	p, err := parsePkgPayload(f.GetPayload())
	if err != nil {
		item.Success, item.Log = false, err.Error()
		return item
	}
	addLog("软件包修复: %s → %s (%s) 关联 %s", p.PkgName, p.TargetVersion, p.RepoType, p.CveID)

	// 1. 前置检查：磁盘余量
	if free, err := freeDiskMB(); err == nil && free < minFreeDiskMB {
		item.Success, item.Log = false,
			fmt.Sprintf("磁盘余量不足（%.0fMB < %dMB），已中止（未做任何变更）", free, minFreeDiskMB)
		return item
	}

	// 2. 下载补丁 + sha256 校验
	tmp, err := downloadPatch(workDir, p)
	if err != nil {
		addLog("补丁下载/校验失败: %v", err)
		item.Success, item.Log = false, joinLog(lines)
		return item
	}
	defer os.Remove(tmp)
	addLog("补丁下载并校验通过: %s", filepath.Base(tmp))

	// 3. 记录旧版本（回滚参考；查询失败不阻断——可能未安装）
	if old := queryPkgVersion(p.PkgName); old != "" {
		addLog("当前版本: %s（人工降级参考）", old)
	} else {
		addLog("当前未安装 %s（新装）", p.PkgName)
	}

	// 4. 安装（平台实现；失败不回滚，如实上报）
	reboot, err := installPatch(p, tmp, func(format string, args ...any) { addLog(format, args...) })
	item.RebootRequired = reboot
	if err != nil {
		addLog("安装失败: %v（不自动回滚，请人工检查依赖/窗口后重试）", err)
		item.Success, item.Log = false, joinLog(lines)
		log.Warn("软件包修复失败", "pkg", p.PkgName, "err", err)
		return item
	}

	// 5. 版本复核（msu 无直接查询手段，标记 installed 由平台侧重扫验证）
	if got := queryPkgVersion(p.PkgName); got != "" {
		if p.RepoType != "msu" && got != p.TargetVersion {
			addLog("复核版本不符: 期望 %s 实际 %s", p.TargetVersion, got)
			item.Success, item.Verified, item.Log = false, false, joinLog(lines)
			return item
		}
		item.Verified = true
		addLog("复核通过: %s", got)
	} else {
		addLog("无法查询安装后版本（%s），标记待平台重扫验证", p.RepoType)
	}

	item.Success, item.Log = true, joinLog(lines)
	log.Info("软件包修复完成", "pkg", p.PkgName, "version", p.TargetVersion, "reboot", reboot)
	return item
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
	case "rpm", "deb", "msu":
	default:
		return nil, fmt.Errorf("不支持的补丁类型: %s", p.RepoType)
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
