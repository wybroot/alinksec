// Package upgrade Agent 自升级（docs/01 §6.4）：
// 独立 systemd/SCM 看护 → 校验替换 → 新版本健康确认或自动恢复旧版本。
package upgrade

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/alinksec/alinksec-agent/internal/securehttp"
)

const chunkSize = 256 << 10 // 256KB/20ms ≈ 12.5MB/s 限速（避开 virusscan 全速，升级更温和）

// Apply stages one upgrade and starts an independent native recovery service.
// Success here means accepted, not healthy: the watchdog emits the final result.
func Apply(workDir, downloadURL, wantSHA, version, commandID string) (string, error) {
	if downloadURL == "" || !validHash(wantSHA) || version == "" || len(version) > 128 || commandID == "" || len(commandID) > 256 {
		return "", fmt.Errorf("invalid upgrade download, SHA256, version or command identity")
	}
	absolute, err := filepath.Abs(workDir)
	if err != nil {
		return "", err
	}
	workDir, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	m := nativeManager{}
	if err := m.verify(exe); err != nil {
		return "", err
	}
	unlock, err := lockUpgrade(workDir)
	if err != nil {
		return "", err
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	if current, err := loadTransaction(workDir); err == nil {
		if current.Phase != "finished" {
			return "", fmt.Errorf("an upgrade or rollback is already pending")
		}
		if err := m.remove(helperPath(workDir, current.ID), workDir); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	results, err := Outcomes(workDir)
	if err != nil {
		return "", err
	}
	for _, r := range results {
		if r.CommandID == commandID {
			return "", fmt.Errorf("upgrade command already completed")
		}
	}
	if len(results) >= maxResults {
		return "", fmt.Errorf("upgrade result archive is full; retain records externally before removing reviewed results")
	}
	for _, r := range results {
		if r.Complete {
			os.Remove(helperPath(workDir, r.ID))
			os.Remove(readyPath(workDir, r.ID))
			os.Remove(filepath.Dir(helperPath(workDir, r.ID)))
		}
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	if err := privateDir(filepath.Join(upgradeDir(workDir), id)); err != nil {
		return "", err
	}
	prepared := false
	defer func() {
		if !prepared {
			os.RemoveAll(filepath.Join(upgradeDir(workDir), id))
		}
	}()
	if err := privateDir(filepath.Join(upgradeDir(workDir), "results")); err != nil {
		return "", err
	}
	newPath := exe + ".upgrade-" + id + ".new"
	if err := downloadLimited(workDir, downloadURL, newPath); err != nil {
		var requestError *url.Error
		if errors.As(err, &requestError) {
			return "", fmt.Errorf("download upgrade: %s: %w", requestError.Op, requestError.Err)
		}
		return "", fmt.Errorf("download upgrade: %w", err)
	}
	defer os.Remove(newPath)
	if err := verifySHA256(newPath, wantSHA); err != nil {
		return "", err
	}
	if err := verifyPlatform(newPath, runtime.GOOS, runtime.GOARCH); err != nil {
		return "", err
	}
	info, err := os.Stat(exe)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(newPath, info.Mode().Perm()); err != nil {
		return "", err
	}
	oldHash, err := fileSHA256(exe)
	if err != nil {
		return "", err
	}
	if err := copyHelper(exe, helperPath(workDir, id)); err != nil {
		return "", err
	}
	originalStarted, err := processStarted(os.Getpid())
	if err != nil {
		return "", err
	}
	tx := &transaction{ID: id, CommandID: commandID, Executable: exe, OldHash: oldHash, NewHash: wantSHA, Version: version, OriginalPID: os.Getpid(), OriginalStarted: originalStarted, Deadline: time.Now().Add(startupTimeout), Phase: "prepared"}
	if err := writeJSON(statePath(workDir), tx); err != nil {
		return "", err
	}
	prepared = true
	unlock()
	locked = false
	abort := func(cause error) (string, error) {
		release, e := lockUpgrade(workDir)
		if e != nil {
			return "", errors.Join(cause, e)
		}
		_, e = finish(workDir, tx, Outcome{Message: "upgrade preparation failed; original Agent unchanged: " + cause.Error()}, time.Now())
		release()
		cleanup := m.remove(helperPath(workDir, id), workDir)
		return "", errors.Join(cause, e, cleanup)
	}
	if err := m.install(helperPath(workDir, id), workDir); err != nil {
		return abort(err)
	}
	readyDeadline := time.Now().Add(10 * time.Second)
	for {
		var ready string
		if err := readJSON(readyPath(workDir, id), &ready); err == nil && ready == id {
			break
		}
		if time.Now().After(readyDeadline) {
			return abort(fmt.Errorf("independent upgrade watchdog did not become ready"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	unlock, err = lockUpgrade(workDir)
	if err != nil {
		return "", err
	}
	locked = true
	current, err := loadTransaction(workDir)
	if err != nil {
		return "", err
	}
	if current.ID != id || current.Phase != "prepared" || !time.Now().Before(current.Deadline) {
		return "", fmt.Errorf("upgrade preparation expired or changed")
	}
	// Journal pending before either rename; recovery handles interruption at each
	// file boundary, including a temporarily absent executable.
	tx.Phase = "pending"
	if err := writeJSON(statePath(workDir), tx); err != nil {
		return "", err
	}
	oldPath := exe + ".old"
	if old, err := os.Lstat(oldPath); err == nil {
		if !old.Mode().IsRegular() {
			return "", fmt.Errorf("old Agent path is not a regular file")
		}
		if err := os.Remove(oldPath); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := moveExecutable(exe, oldPath); err != nil {
		return "", fmt.Errorf("backup Agent: %w", err)
	}
	if err := moveExecutable(newPath, exe); err != nil {
		return "", errors.Join(fmt.Errorf("replace Agent: %w", err), moveExecutable(oldPath, exe))
	}
	unlock()
	locked = false
	go func() { time.Sleep(time.Second); os.Exit(0) }()
	return "upgrade accepted; waiting for new Agent startup and watchdog confirmation", nil
}

func copyHelper(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(in, (256<<20)+1))
	if err == nil {
		err = out.Sync()
	}
	if e := out.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	want, err := fileSHA256(src)
	if err != nil {
		return err
	}
	return verifySHA256(dst, want)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

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
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			os.Remove(dst)
		}
	}()
	buf := make([]byte, chunkSize)
	total := 0
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			total += n
			if total > 128<<20 {
				return fmt.Errorf("upgrade package exceeds 128 MiB")
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			time.Sleep(20 * time.Millisecond)
		}
		if rerr == io.EOF {
			if err := f.Sync(); err != nil {
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			complete = true
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func verifySHA256(path, want string) error {
	if !validHash(want) {
		return fmt.Errorf("invalid expected SHA256")
	}
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
