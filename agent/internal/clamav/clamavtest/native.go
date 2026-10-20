package clamavtest

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/clamav"
)

const Marker = "ALINKSEC-HARMLESS-CLAMAV-NATIVE-MARKER-2026-10"

// Native starts only the explicitly provided test binary, with a private tiny
// custom database. It does not download official definitions or touch services.
func Native(t testing.TB) (clamav.Config, string) {
	t.Helper()
	bin := os.Getenv("ALINKSEC_CLAMAV_TEST_BIN")
	if bin == "" {
		if os.Getenv("ALINKSEC_CLAMAV_NATIVE_REQUIRED") == "true" {
			t.Fatal("missing required native ClamAV binary")
		}
		t.Skip("set ALINKSEC_CLAMAV_TEST_BIN for native fixture")
	}
	if !filepath.IsAbs(bin) {
		t.Fatal("native binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	root := t.TempDir()
	database := filepath.Join(root, "database")
	if err := os.Mkdir(database, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(database, "fixture.ndb"), []byte("AlinkSec.Harmless.Marker:0:*:"+hex.EncodeToString([]byte(Marker))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	conf := fmt.Sprintf("Foreground yes\nDatabaseDirectory %s\nTemporaryDirectory %s\nTCPSocket %d\nTCPAddr 127.0.0.1\nMaxThreads 1\nMaxQueue 2\nStreamMaxLength 20M\nMaxFileSize 20M\nMaxScanSize 1M\nMaxRecursion 4\nMaxFiles 8\nMaxScanTime 2000\nReadTimeout 5\nCommandReadTimeout 5\nSelfCheck 0\nConcurrentDatabaseReload no\nBytecode no\nAlertExceedsMax yes\nAlertEncrypted yes\n", filepath.ToSlash(database), filepath.ToSlash(root), port)
	config := filepath.Join(root, "clamd.conf")
	if err := os.WriteFile(config, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	version, err := exec.CommandContext(ctx, bin, "--config-file="+config, "--version").CombinedOutput()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), "ClamAV 1.4.6") {
		t.Fatalf("native version=%q err=%v", version, err)
	}
	log, err := os.Create(filepath.Join(root, "clamd.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "--config-file="+config)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("native daemon did not exit")
		}
		log.Close()
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-exited:
			exited <- err
			data, _ := os.ReadFile(log.Name())
			t.Fatalf("native daemon exited: %v %s", err, data)
		default:
		}
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(log.Name())
			t.Fatalf("native startup timeout: %s", data)
		}
		time.Sleep(40 * time.Millisecond)
	}
	cfg := Start(t, func(front net.Conn) {
		back, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return
		}
		defer back.Close()
		_ = back.SetDeadline(time.Now().Add(5 * time.Second))
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(back, front)
			if tcp, ok := back.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
			close(done)
		}()
		_, _ = io.Copy(front, back)
		front.Close()
		<-done
	})
	cfg.TimeoutSec = 5
	v, err := clamav.New(cfg).Probe(ctx)
	if err != nil || !strings.HasPrefix(v, "ClamAV 1.4.6") {
		t.Fatalf("native protocol probe=%q err=%v", v, err)
	}
	return cfg, v
}
