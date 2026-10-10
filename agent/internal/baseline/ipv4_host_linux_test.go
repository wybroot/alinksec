//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ipv4ProcFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"thread-self/ns", "sys/net/ipv4/conf/all", "sys/net/ipv4/conf/default", "sys/net/ipv4/conf/lo", "sys/net/ipv4/conf/eth0.1"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{"thread-self/ns/net": "fixture", "sys/net/ipv4/ip_forward": "0\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"all", "default", "lo", "eth0.1"} {
		for param, value := range map[string]string{"rp_filter": "1\n", "forwarding": "0\n"} {
			if err := os.WriteFile(filepath.Join(root, "sys/net/ipv4/conf", name, param), []byte(value), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}
func TestIPv4HostBoundedProcReader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(string) error
	}{
		{"good", func(root string) error { return nil }},
		{"unknown", func(root string) error {
			return os.WriteFile(filepath.Join(root, "sys/net/ipv4/ip_forward"), []byte("2\n"), 0644)
		}},
		{"too_large", func(root string) error {
			return os.WriteFile(filepath.Join(root, "sys/net/ipv4/ip_forward"), make([]byte, 65), 0644)
		}},
		{"multiple_lines", func(root string) error {
			return os.WriteFile(filepath.Join(root, "sys/net/ipv4/ip_forward"), []byte("0\n0\n"), 0644)
		}},
		{"missing", func(root string) error { return os.Remove(filepath.Join(root, "sys/net/ipv4/conf/lo/rp_filter")) }},
		{"symlink", func(root string) error {
			path := filepath.Join(root, "sys/net/ipv4/ip_forward")
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("conf/lo/forwarding", path)
		}},
		{"ancestor_symlink", func(root string) error {
			path := filepath.Join(root, "sys/net/ipv4/conf/lo")
			if err := os.Rename(path, path+"-saved"); err != nil {
				return err
			}
			return os.Symlink("lo-saved", path)
		}},
		{"hardlink", func(root string) error {
			return os.Link(filepath.Join(root, "sys/net/ipv4/ip_forward"), filepath.Join(root, "linked"))
		}},
		{"fifo", func(root string) error {
			path := filepath.Join(root, "sys/net/ipv4/ip_forward")
			if err := os.Remove(path); err != nil {
				return err
			}
			return unix.Mkfifo(path, 0644)
		}},
		{"too_many_interfaces", func(root string) error {
			for i := 0; i < 17; i++ {
				if err := os.Mkdir(filepath.Join(root, "sys/net/ipv4/conf", fmt.Sprintf("extra%d", i)), 0755); err != nil {
					return err
				}
			}
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := ipv4ProcFixture(t)
			if err := tc.mutate(root); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := readIPv4HostSnapshot(ctx, root, false)
			if (err == nil) != (tc.name == "good") {
				t.Fatal(err)
			}
			if tc.name == "good" {
				if _, err := readIPv4HostSnapshot(ctx, root, true); err == nil {
					t.Fatal("ordinary disk accepted as procfs")
				}
			}
		})
	}
}
