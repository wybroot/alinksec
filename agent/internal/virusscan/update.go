// Package virusscan 特征库更新（docs/05 §1.2）：
// 限速下载（2MB/s）→ sha256 校验 → 本地原子替换（InstallDB）→ ACK。
// 断网沿用本地库；下载失败不影响存量引擎。
package virusscan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securehttp"
)

// downloadLimitRate 特征包下载限速（docs/05：2MB/s，内网带宽敏感）
const downloadLimitRate = 2 << 20

// downloadTimeout 单次下载总超时（20MB 包 @2MB/s ≈ 10s，留足余量）
const downloadTimeout = 10 * time.Minute

// UpdateDB 下载并安装特征库包；返回是否发生实际更新。
// downloadURL 为服务端下发的完整地址（M2：服务端静态文件端点；M3：MinIO 预签名）。
func UpdateDB(ctx context.Context, workDir, downloadURL, expectSha256 string, log *slog.Logger) error {
	if downloadURL == "" {
		return fmt.Errorf("下载地址为空")
	}
	dctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	resp, err := securehttp.Get(dctx, workDir, downloadURL, downloadTimeout)
	if err != nil {
		return fmt.Errorf("下载特征包: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("下载特征包: HTTP %d", resp.StatusCode)
	}

	// 落盘到临时文件（virus/pkg.tmp）
	pkgDir := filepath.Join(workDir, "virus")
	if err := os.MkdirAll(pkgDir, 0700); err != nil {
		return fmt.Errorf("创建目录: %w", err)
	}
	tmp := filepath.Join(pkgDir, "pkg.tmp")
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("写临时文件: %w", err)
	}
	// 限速读：每 2MB sleep 1s
	if _, err := copyLimited(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("下载写入: %w", err)
	}
	out.Close()

	if err := InstallDB(workDir, tmp, expectSha256); err != nil {
		os.Remove(tmp)
		return err
	}
	os.Remove(tmp)
	log.Info("特征库已更新", "version", LocalVersion(workDir))
	return nil
}

// copyLimited 限速拷贝（2MB/s）
func copyLimited(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 256<<10)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			if total%(2<<20) < int64(n) {
				time.Sleep(time.Second)
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}
