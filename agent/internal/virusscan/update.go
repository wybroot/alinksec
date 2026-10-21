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

const downloadLimitRate = 2 << 20
const downloadTimeout = 10 * time.Minute
const maxPackageBytes int64 = 20 << 20

type UpdateSpec struct {
	Version, URL, SHA256              string
	DeltaURL, DeltaSHA256             string
	BaseVersion, BaseContent, Content string
}

// Receipts contain no URLs or credentials. Only a verified final target is
// reported complete; a failed candidate leaves the previous library untouched.
type UpdateReceipt struct {
	Mode       string `json:"mode"`
	Version    string `json:"version"`
	Content    string `json:"content_sha256"`
	Downloaded int64  `json:"downloaded_bytes"`
	Fallback   string `json:"fallback,omitempty"`
}

func UpdateRelease(ctx context.Context, workDir string, spec UpdateSpec) (UpdateReceipt, error) {
	r := UpdateReceipt{Version: spec.Version, Content: spec.Content}
	_, urlErr := securehttp.ValidateURL(spec.URL)
	if urlErr != nil || !signatureVersion.MatchString(spec.Version) || !validDigest(spec.SHA256) || !validDigest(spec.Content) {
		return r, fmt.Errorf("invalid release identity")
	}
	if spec.DeltaURL != "" && (!validDigest(spec.DeltaSHA256) || !validDigest(spec.BaseContent) || !signatureVersion.MatchString(spec.BaseVersion) || spec.BaseVersion == spec.Version) {
		return r, fmt.Errorf("invalid delta identity")
	}
	if spec.DeltaURL != "" {
		if _, err := securehttp.ValidateURL(spec.DeltaURL); err != nil {
			return r, fmt.Errorf("invalid delta URL")
		}
	}
	dctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	installMu.Lock()
	err := recoverDB(workDir)
	current := parseDB(DBDir(workDir))
	digest, digestErr := contentDigest(DBDir(workDir))
	installMu.Unlock()
	if err != nil {
		return r, err
	}
	if current.Valid && digestErr == nil && current.Version == spec.Version && digest == spec.Content {
		r.Mode = "already-current"
		return r, nil
	}
	if spec.DeltaURL != "" {
		if !current.Valid || digestErr != nil || current.Version != spec.BaseVersion || digest != spec.BaseContent {
			r.Fallback = "base-mismatch"
		} else {
			pkg, n, downloadErr := downloadPackage(dctx, workDir, spec.DeltaURL)
			r.Downloaded += n
			if downloadErr == nil {
				downloadErr = installDB(workDir, pkg, spec.DeltaSHA256, &spec, true)
			}
			if pkg != "" {
				os.Remove(pkg)
			}
			if downloadErr == nil {
				r.Mode = "delta"
				return r, nil
			}
			r.Fallback = "delta-failed"
		}
	}
	if dctx.Err() != nil {
		return r, dctx.Err()
	}
	pkg, n, err := downloadPackage(dctx, workDir, spec.URL)
	r.Downloaded += n
	if pkg != "" {
		defer os.Remove(pkg)
	}
	if err != nil {
		return r, err
	}
	if err = installDB(workDir, pkg, spec.SHA256, &spec, false); err != nil {
		return r, err
	}
	r.Mode = "full"
	return r, nil
}

// Legacy commands retain the complete-package path. New commands also pin the
// version and exact installed content rather than trusting a version label.
func UpdateDB(ctx context.Context, workDir, url, digest string, log *slog.Logger) error {
	if !validDigest(digest) {
		return fmt.Errorf("invalid package digest")
	}
	dctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	pkg, _, err := downloadPackage(dctx, workDir, url)
	if pkg != "" {
		defer os.Remove(pkg)
	}
	if err == nil {
		err = InstallDB(workDir, pkg, digest)
	}
	if err == nil && log != nil {
		log.Info("特征库已更新", "version", LocalVersion(workDir))
	}
	return err
}

func downloadPackage(ctx context.Context, workDir, url string) (string, int64, error) {
	resp, err := securehttp.Get(ctx, workDir, url, downloadTimeout)
	if err != nil {
		return "", 0, fmt.Errorf("signature download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.ContentLength > maxPackageBytes {
		return "", 0, fmt.Errorf("signature download response rejected")
	}
	dir := filepath.Join(workDir, "virus")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", 0, err
	}
	out, err := os.CreateTemp(dir, "pkg-*.tmp")
	if err != nil {
		return "", 0, err
	}
	path := out.Name()
	n, err := copyLimited(ctx, out, io.LimitReader(resp.Body, maxPackageBytes+1))
	if n > maxPackageBytes {
		err = fmt.Errorf("signature download exceeds 20MiB")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return "", n, err
	}
	return path, n, nil
}

func copyLimited(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 256<<10)
	var total int64
	start := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			written, err := dst.Write(buf[:n])
			total += int64(written)
			if err != nil {
				return total, err
			}
			if written != n {
				return total, io.ErrShortWrite
			}
			if delay := time.Duration(total)*time.Second/downloadLimitRate - time.Since(start); delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return total, ctx.Err()
				case <-timer.C:
				}
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
