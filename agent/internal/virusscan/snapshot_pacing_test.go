package virusscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/resources"
)

func TestSnapshotPacingFitsTheFileAndEOFAllowance(t *testing.T) {
	for _, size := range []int{0, 1, 1040, 64 << 10, (64 << 10) + 17} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte("x"), size)
			path := filepath.Join(t.TempDir(), "ordinary")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			charged := 0
			ctx := context.WithValue(context.Background(), ioBudgetKey{}, func(_ context.Context, n int) error {
				charged += n
				if n < 1 || n > 64<<10 || charged > size+1 {
					return fmt.Errorf("read exceeded file and EOF allowance")
				}
				return nil
			})
			var streamed bytes.Buffer
			s, err := readSnapshotScopedSink(ctx, path, 1<<20, 1<<20, true, "", "", &streamed)
			sum := sha256.Sum256(data)
			if err != nil || s.sum != hex.EncodeToString(sum[:]) || s.bytesRead != uint64(size) || !bytes.Equal(streamed.Bytes(), data) || charged != size+1 {
				t.Fatalf("full snapshot did not fit allowance: bytes=%d charged=%d streamed=%d sum=%s err=%v", s.bytesRead, charged, streamed.Len(), s.sum, err)
			}
		})
	}
}

func TestSnapshotPacingRejectsGrowthAtEOF(t *testing.T) {
	data := bytes.Repeat([]byte("x"), (64<<10)+17)
	path := filepath.Join(t.TempDir(), "growing")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	charged := 0
	var mutationErr error
	ctx := context.WithValue(context.Background(), ioBudgetKey{}, func(_ context.Context, n int) error {
		charged += n
		if charged == len(data)+1 {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				mutationErr = err
				return err
			}
			_, err = f.Write([]byte("!"))
			closeErr := f.Close()
			if err != nil {
				return err
			}
			return closeErr
		}
		return nil
	})
	var streamed bytes.Buffer
	s, err := readSnapshotScopedSink(ctx, path, 1<<20, 1<<20, false, "", "", &streamed)
	if runtime.GOOS == "windows" {
		if mutationErr == nil || err == nil || s.sum != "" || s.bytesRead != uint64(len(data)) || !bytes.Equal(streamed.Bytes(), data) {
			t.Fatalf("pinned Windows reader did not reject concurrent append: snapshot=%+v mutation=%v err=%v", s, mutationErr, err)
		}
		return
	}
	if snapshotIssueCode(ctx, err) != "file_changed" || s.sum != "" || s.bytesRead != uint64(len(data)+1) || !bytes.Equal(streamed.Bytes(), data) {
		t.Fatalf("growth accepted or sent beyond pinned length: bytes=%d charged=%d streamed=%d err=%v", s.bytesRead, charged, streamed.Len(), err)
	}
}

func TestSnapshotPacingRejectsTruncatedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shrinking")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), (64<<10)+17), 0600); err != nil {
		t.Fatal(err)
	}
	reads := 0
	var mutationErr error
	ctx := context.WithValue(context.Background(), ioBudgetKey{}, func(context.Context, int) error {
		reads++
		if reads == 2 {
			mutationErr = os.Truncate(path, 64<<10)
			return mutationErr
		}
		return nil
	})
	s, err := readSnapshotScopedSink(ctx, path, 1<<20, 1<<20, false, "", "", io.Discard)
	if runtime.GOOS == "windows" {
		if mutationErr == nil || err == nil || s.sum != "" || s.bytesRead != 64<<10 {
			t.Fatalf("pinned Windows reader did not reject concurrent truncation: snapshot=%+v mutation=%v err=%v", s, mutationErr, err)
		}
		return
	}
	if snapshotIssueCode(ctx, err) != "file_changed" || s.sum != "" || s.bytesRead != 64<<10 {
		t.Fatalf("short input accepted: bytes=%d err=%v", s.bytesRead, err)
	}
}

func TestSnapshotPacingRequiresTheEOFCheckBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 1040), 0600); err != nil {
		t.Fatal(err)
	}
	charged := 0
	ctx := context.WithValue(context.Background(), ioBudgetKey{}, func(_ context.Context, n int) error {
		charged += n
		if charged > 1040 {
			return context.DeadlineExceeded
		}
		return nil
	})
	s, err := readSnapshotScopedSink(ctx, path, 1<<20, 1<<20, true, "", "", io.Discard)
	if err == nil || s.sum != "" || s.bytesRead != 1040 || charged != 1041 {
		t.Fatalf("missing EOF allowance looked complete: bytes=%d charged=%d err=%v", s.bytesRead, charged, err)
	}
}

func BenchmarkPacedSnapshotTail(b *testing.B) {
	for _, size := range []int{1040, (64 << 10) + 17} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "ordinary")
			data := bytes.Repeat([]byte("x"), size)
			if err := os.WriteFile(path, data, 0600); err != nil {
				b.Fatal(err)
			}
			// Exercise real pacing at factor 8 without generating host pressure.
			g := resources.New(resources.Config{})
			g.Observe(resources.Sample{At: time.Now(), RSSBytes: 100 << 20}, nil)
			if g.State().Factor != 8 {
				b.Fatal("benchmark requires factor 8")
			}
			charged := 0
			wait := func(ctx context.Context, n int) error { charged += n; return g.WaitIO(ctx, n) }
			sum := sha256.Sum256(data)
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				s, err := readSnapshotScopedSink(context.WithValue(ctx, ioBudgetKey{}, wait), path, 1<<20, 1<<20, true, "", "", io.Discard)
				cancel()
				if err != nil || s.bytesRead != uint64(size) || s.sum != hex.EncodeToString(sum[:]) {
					b.Fatal("incomplete snapshot", s.bytesRead, err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(charged)/float64(b.N), "io-request-B/op")
		})
	}
}
