// Package upgrade Agent 自升级（docs/01 §6.4）：
// 限速下载 → SHA256 校验 → 落盘 .new → 原子替换（旧版本保留 .old，启动失败可人工回滚）
// → 退出进程由服务管理器拉起新版本（Linux systemd Restart=always / Windows SCM 恢复策略）。
package upgrade

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securehttp"
)

const chunkSize = 256 << 10 // 256KB/20ms ≈ 12.5MB/s 限速（避开 virusscan 全速，升级更温和）

// Apply 执行升级：下载校验 + 替换 + 触发重启。返回给平台的完成消息。
// 成功路径下进程即将退出，调用方应立即回 DONE ACK。
func Apply(workDir, downloadURL, wantSHA, version string) (string, error) {
	if downloadURL == "" || wantSHA == "" {
		return "", fmt.Errorf("download_url/sha256 为空")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("定位当前二进制失败: %w", err)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	newPath := exe + ".new"
	oldPath := exe + ".old"

	if err := downloadLimited(workDir, downloadURL, newPath); err != nil {
		os.Remove(newPath)
		return "", fmt.Errorf("下载失败: %w", err)
	}
	if err := verifySHA256(newPath, wantSHA); err != nil {
		os.Remove(newPath)
		return "", err
	}
	if err := verifyPlatform(newPath, runtime.GOOS, runtime.GOARCH); err != nil {
		os.Remove(newPath)
		return "", err
	}
	// 权限对齐当前可执行文件（Windows 忽略）
	if info, err := os.Stat(exe); err == nil {
		_ = os.Chmod(newPath, info.Mode())
	}
	// 保留旧版本用于回滚
	_ = os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return "", fmt.Errorf("备份当前二进制失败: %w", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(oldPath, exe) // 回滚
		os.Remove(newPath)
		return "", fmt.Errorf("替换二进制失败: %w", err)
	}
	// Windows：运行中 exe 可 rename 不可删，.old 保留至下次升级；Linux 同理由本函数清理
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0) // 退出 → systemd/SCM 自动拉起新版本（docs §6.2 自愈）
	}()
	return fmt.Sprintf("upgraded %s -> %s, restarting (%s)", currentVersionHint(), version, runtime.GOOS), nil
}

// Rollback 回滚到上一版本（人工触发场景：新版本启动失败后由运维执行 <exe>.old 交换）
func Rollback() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	oldPath := exe + ".old"
	if _, err := os.Stat(oldPath); err != nil {
		return "", fmt.Errorf("无旧版本备份")
	}
	bad := exe + ".bad"
	_ = os.Remove(bad)
	_ = os.Rename(exe, bad)
	if err := os.Rename(oldPath, exe); err != nil {
		_ = os.Rename(bad, exe)
		return "", err
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
	return "rolled back to previous version, restarting", nil
}

func currentVersionHint() string { return "current" }

// Reject a mislabeled package before replacing the running Agent.
func verifyPlatform(path, wantOS, wantArch string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取升级包平台失败: %w", err)
	}
	var goos, goarch string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			goos = setting.Value
		case "GOARCH":
			goarch = setting.Value
		}
	}
	if goos != wantOS || goarch != wantArch {
		return fmt.Errorf("升级包平台 %s/%s 与当前 Agent %s/%s 不匹配", goos, goarch, wantOS, wantArch)
	}
	return nil
}

// downloadLimited 限速下载到目标路径（与 virusscan.update 同模式：读 chunk → sleep）
func downloadLimited(workDir, url, dst string) error {
	resp, err := securehttp.Get(context.Background(), workDir, url, 30*time.Minute)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, chunkSize)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			time.Sleep(20 * time.Millisecond)
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("sha256 不匹配: got=%s want=%s", got[:12], want[:12])
	}
	return nil
}
