package clamav_test

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/clamav"
	"github.com/alinksec/alinksec-agent/internal/clamav/clamavtest"
)

const version = "ClamAV 1.4.6/fixture/Mon Oct 19 00:00:00 2026"

func fixture(t *testing.T, response string, mutate bool) (*clamav.Client, *atomic.Int32) {
	var scans atomic.Int32
	cfg := clamavtest.Start(t, func(c net.Conn) {
		cmd, err := clamavtest.Command(c)
		if err != nil {
			return
		}
		switch cmd {
		case "zVERSION\x00":
			v := version
			if mutate && scans.Load() > 0 {
				v += "-changed"
			}
			clamavtest.Reply(c, v)
		case "zINSTREAM\x00":
			b, err := clamavtest.Stream(c)
			if err != nil {
				return
			}
			if string(b) != "harmless fixture" {
				return
			}
			scans.Add(1)
			clamavtest.Reply(c, response)
		}
	})
	return clamav.New(cfg), &scans
}
func consume(_ context.Context, w io.Writer) error {
	_, err := io.WriteString(w, "harmless fixture")
	return err
}
func TestStreamVerdictsAndVersionBinding(t *testing.T) {
	for _, tc := range []struct {
		reply, name, code string
		mutate            bool
	}{
		{"stream: OK", "", "", false}, {"stream: Test.Marker FOUND", "Test.Marker", "", false},
		{"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND", "", "clamav_incomplete", false},
		{"stream: Heuristics.Encrypted.Zip FOUND", "", "clamav_incomplete", false},
		{"INSTREAM size limit exceeded. ERROR", "", "clamav_scan_error", false},
		{"stream: OK extra", "", "clamav_scan_error", false}, {"stream: bad\nname FOUND", "", "clamav_protocol", false},
		{"stream: " + strings.Repeat("x", 4096) + " FOUND", "", "clamav_protocol", false},
		{"stream: Test.Marker FOUND", "", "clamav_version_changed", true},
	} {
		t.Run(tc.code+tc.reply[:min(len(tc.reply), 30)], func(t *testing.T) {
			c, n := fixture(t, tc.reply, tc.mutate)
			name, err := c.Scan(context.Background(), version, consume)
			if name != tc.name || clamav.Code(err) != tc.code || n.Load() != 1 {
				t.Fatalf("name=%q error=%v scans=%d", name, err, n.Load())
			}
			s := c.Status()
			if s.Scans != 1 || s.Failures != uint64(boolInt(tc.code != "")) {
				t.Fatalf("status=%+v", s)
			}
		})
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func TestVersionMismatchDoesNotSendContent(t *testing.T) {
	c, n := fixture(t, "stream: OK", false)
	called := false
	_, err := c.Scan(context.Background(), "ClamAV different", func(ctx context.Context, w io.Writer) error { called = true; return consume(ctx, w) })
	if clamav.Code(err) != "clamav_version_changed" || called || n.Load() != 0 {
		t.Fatalf("err=%v content=%v", err, called)
	}
}
func TestTLSConfigAndCancellation(t *testing.T) {
	for _, addr := range []string{"localhost:3310", "192.0.2.1:3310", "0.0.0.0:3310", "127.0.0.1:0", "[::]:3310"} {
		if (clamav.Config{Enabled: true, Address: addr, ServerCertSHA256: strings.Repeat("a", 64)}).Validate() == nil {
			t.Fatal(addr)
		}
	}
	cfg := clamavtest.Start(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	wrong := cfg
	wrong.ServerCertSHA256 = strings.Repeat("0", 64)
	if _, err := clamav.New(wrong).Probe(context.Background()); clamav.Code(err) != "clamav_tls_identity" {
		t.Fatalf("wrong pin=%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := clamav.New(cfg).Probe(ctx); err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancellation=%v duration=%v", err, time.Since(start))
	}
}
func TestScanSerializationAndCancelledWaiter(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	cfg := clamavtest.Start(t, func(c net.Conn) {
		cmd, _ := clamavtest.Command(c)
		if cmd == "zVERSION\x00" {
			clamavtest.Reply(c, version)
			return
		}
		if cmd == "zINSTREAM\x00" {
			close(entered)
			<-release
			_, _ = clamavtest.Stream(c)
			clamavtest.Reply(c, "stream: OK")
		}
	})
	c := clamav.New(cfg)
	done := make(chan error, 1)
	go func() { _, err := c.Scan(context.Background(), version, consume); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("stream did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	called := false
	_, err := c.Scan(ctx, version, func(_ context.Context, w io.Writer) error { called = true; return nil })
	close(release)
	if err == nil || called {
		t.Fatalf("waiter err=%v consumed=%v", err, called)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFileDeadlineReachesResourceWait(t *testing.T) {
	c, _ := fixture(t, "stream: OK", false)
	started := time.Now()
	_, err := c.Scan(context.Background(), version, func(scanCtx context.Context, w io.Writer) error {
		deadline, ok := scanCtx.Deadline()
		if !ok || deadline.Sub(started) > 2100*time.Millisecond {
			t.Error("file timeout did not reach resource wait")
		}
		<-scanCtx.Done()
		return scanCtx.Err()
	})
	if clamav.Code(err) != "clamav_timeout" || time.Since(started) > 3*time.Second {
		t.Fatalf("resource wait deadline err=%v duration=%v", err, time.Since(started))
	}
}
