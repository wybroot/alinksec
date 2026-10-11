//go:build linux

package baseline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func appArmorFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, raw := range map[string]string{"module/apparmor/parameters/enabled": "Y\n", "module/apparmor/parameters/mode": "enforce", "kernel/security/lsm": "capability,apparmor\n", "kernel/security/apparmor/.ns_level": "0\n", "kernel/security/apparmor/.stacked": "no\n", "kernel/security/apparmor/.ns_stacked": "no\n", "kernel/security/apparmor/profiles": "example (enforce)\n"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestAppArmorProtectedKernelReader(t *testing.T) {
	for _, tc := range []string{"normal", "missing", "symlink_file", "symlink_parent", "fifo", "world_write", "hardlink", "too_large", "fake_kernel_fs", "cancelled", "replaced_path", "parent_replaced", "mode_changed"} {
		t.Run(tc, func(t *testing.T) {
			root := appArmorFixture(t)
			path := filepath.Join(root, "kernel/security/apparmor/profiles")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var beforeStable func()
			switch tc {
			case "missing":
				os.Remove(path)
			case "symlink_file":
				os.Rename(path, path+".outside")
				os.Symlink(path+".outside", path)
			case "symlink_parent":
				dir := filepath.Dir(path)
				os.Rename(dir, dir+".outside")
				os.Symlink(dir+".outside", dir)
			case "fifo":
				os.Remove(path)
				if err := unix.Mkfifo(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "world_write":
				os.Chmod(path, 0666)
			case "hardlink":
				os.Link(path, path+".other")
			case "too_large":
				os.WriteFile(path, make([]byte, appArmorMaxBytes+1), 0644)
			case "cancelled":
				cancel()
			case "replaced_path":
				beforeStable = func() { os.Rename(path, path+".old"); os.WriteFile(path, []byte("new (enforce)\n"), 0644) }
			case "parent_replaced":
				beforeStable = func() { os.Rename(filepath.Dir(path), filepath.Dir(path)+".old"); os.Mkdir(filepath.Dir(path), 0755) }
			case "mode_changed":
				beforeStable = func() { os.Chmod(path, 0666) }
			}
			s, err := readAppArmorInputs(ctx, root, tc == "fake_kernel_fs", beforeStable)
			if tc == "normal" {
				if err != nil || !evaluateAppArmor(s).Passed {
					t.Fatal(s, err)
				}
			} else if err == nil {
				t.Fatal("reader accepted", tc)
			}
		})
	}
	root := appArmorFixture(t)
	os.WriteFile(filepath.Join(root, "module/apparmor/parameters/enabled"), []byte("N\n"), 0644)
	os.WriteFile(filepath.Join(root, "kernel/security/lsm"), []byte("capability\n"), 0644)
	os.RemoveAll(filepath.Join(root, "kernel/security/apparmor"))
	s, err := readAppArmorSnapshot(context.Background(), root, false)
	if err != nil || evaluateAppArmor(s).Error || evaluateAppArmor(s).Passed {
		t.Fatal(s, err)
	}
}
