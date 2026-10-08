//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func aptProbe(context.Context, int) ItemResult { return ItemResult{Actual: "confirmed"} }
func aptFixture(t *testing.T, main *string, parts map[string]string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("numeric UID0 fixture requires root")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "etc/apt/apt.conf.d")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, raw := range parts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if main != nil {
		if err := os.WriteFile(filepath.Join(root, "etc/apt/apt.conf"), []byte(*main), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type aptCase struct {
	name                   string
	main                   *string
	parts                  map[string]string
	aptU, aptF, getU, getF bool
}

func aptCases() []aptCase {
	s := func(v string) *string { return &v }
	return []aptCase{
		{name: "vendor-defaults"},
		{name: "explicit-false", main: s("APT::Get::AllowUnauthenticated \"false\"; APT::Get::Force-Yes \"0\";\n")},
		{name: "global-true", main: s("APT::Get::AllowUnauthenticated \"true\";\n"), aptU: true, getU: true},
		{name: "force-yes", main: s("APT::Get::Force-Yes \"YES\";\n"), aptF: true, getF: true},
		{name: "nested-case", main: s("apt { get { allowunauthenticated \"ON\"; force-yes \"off\"; }; };\n"), aptU: true, getU: true},
		{name: "binary-apt", main: s("Binary::apt::APT::Get::AllowUnauthenticated \"true\";\n"), aptU: true},
		{name: "binary-get", main: s("Binary { apt-get { APT::Get::Force-Yes \"with\"; }; };\n"), getF: true},
		{name: "binary-over-global", main: s("APT::Get::AllowUnauthenticated \"true\"; Binary::apt::APT::Get::AllowUnauthenticated \"disable\";\n"), getU: true},
		{name: "binary-apt-config-ignored", main: s("Binary::apt-config::APT::Get::AllowUnauthenticated \"true\";\n")},
		{name: "main-last", parts: map[string]string{"zz-final.conf": "APT::Get::Force-Yes \"true\";\n"}, main: s("APT::Get::Force-Yes \"false\";\n")},
		{name: "lexical-order", parts: map[string]string{"10-safe": "APT::Get::AllowUnauthenticated \"false\";\n", "2-unsafe.conf": "APT::Get::AllowUnauthenticated \"true\";\n"}, aptU: true, getU: true},
		{name: "extensions", parts: map[string]string{"20-safe.conf": "APT::Get::Force-Yes \"false\";\n", ".99-hidden.conf": "APT::Get::Force-Yes \"true\";\n", "99-unsafe.bak": "APT::Get::Force-Yes \"true\";\n", "99-unsafe.CONF": "APT::Get::Force-Yes \"true\";\n", "99-unsafe~": "APT::Get::Force-Yes \"true\";\n", "99-unsafe.": "APT::Get::Force-Yes \"true\";\n"}},
		{name: "native-colon-filename", parts: map[string]string{"50:policy.conf": "APT::Get::AllowUnauthenticated \"enable\";\n"}, aptU: true, getU: true},
		{name: "clear-global", main: s("APT::Get::AllowUnauthenticated \"true\"; #clear APT::Get;\n")},
		{name: "clear-binary-empty-overrides", main: s("APT::Get::AllowUnauthenticated \"true\"; Binary::apt::APT::Get::AllowUnauthenticated \"true\"; #clear Binary::apt::APT::Get::AllowUnauthenticated;\n"), getU: true},
		{name: "empty-global-default", main: s("APT::Get::Force-Yes \"\";\n")},
		{name: "clear-then-reassign", main: s("APT::Get::Force-Yes \"true\"; #clear APT; APT::Get::Force-Yes \"false\";\n")},
		{name: "reopen-preserves", main: s("APT { Get { Force-Yes \"true\"; }; }; APT { Get { AllowUnauthenticated \"false\"; }; };\n"), aptF: true, getF: true},
		{name: "comments-hooks-inert", main: s("// APT::Get::AllowUnauthenticated \"true\";\n# APT::Get::Force-Yes \"true\";\n/* ordinary comment\n continued */\nAPT::Get::Force-Yes \"false\"; // true\nDPkg::Pre-Install-Pkgs { \"touch /tmp/alinksec-apt-hook-ran\"; };\nAcquire::http::Proxy \"http://example.invalid/\";\n")},
		{name: "parent-not-inherited", main: s("APT::Get \"true\"; APT::Get::AllowUnauthenticated \"false\";\n")},
	}
}
func TestAPTPolicyCases(t *testing.T) {
	for _, c := range aptCases() {
		t.Run(c.name, func(t *testing.T) {
			root := aptFixture(t, c.main, c.parts)
			r := aptPolicyWithin(aptSpec(), root, aptProbe)
			want := !c.aptU && !c.aptF && !c.getU && !c.getF
			if r.Error || r.Passed != want {
				t.Fatalf("policy %+v", r)
			}
			for _, word := range []string{fmt.Sprintf("apt.allowunauthenticated=%t", c.aptU), fmt.Sprintf("apt.force-yes=%t", c.aptF), fmt.Sprintf("apt-get.allowunauthenticated=%t", c.getU), fmt.Sprintf("apt-get.force-yes=%t", c.getF), "source_trust_state=unverified", "installation_state=unverified"} {
				if !strings.Contains(r.Actual, word) {
					t.Fatalf("missing %s: %+v", word, r)
				}
			}
		})
	}
}
func TestAPTRefusesUnsafeInputs(t *testing.T) {
	for _, kind := range []string{"missing-dir", "symlink", "parent-symlink", "hardlink", "fifo", "writable", "uid", "access-acl", "default-acl", "too-large", "unterminated", "selected-directory", "too-many-parts", "too-many-names", "malformed-irrelevant", "unknown-boolean", "include", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			root := aptFixture(t, nil, map[string]string{"50-policy": "APT::Get::AllowUnauthenticated \"false\";\n"})
			path := filepath.Join(root, "etc/apt/apt.conf.d/50-policy")
			var err error
			switch kind {
			case "missing-dir":
				err = os.Rename(filepath.Dir(path), filepath.Dir(path)+".old")
			case "symlink":
				err = os.Rename(path, path+".bak")
				if err == nil {
					err = os.Symlink(path+".bak", path)
				}
			case "parent-symlink":
				dir := filepath.Dir(path)
				err = os.Rename(dir, dir+".bak")
				if err == nil {
					err = os.Symlink(dir+".bak", dir)
				}
			case "hardlink":
				err = os.Link(path, path+".bak")
			case "fifo":
				err = os.Remove(path)
				if err == nil {
					err = unix.Mkfifo(path, 0600)
				}
			case "writable":
				err = os.Chmod(path, 0666)
			case "uid":
				if os.Getenv("ALINKSEC_APT_NATIVE_REQUIRED") == "true" {
					err = os.Remove(path)
					if err == nil {
						err = os.Rename("/usr/local/lib/alinksec-apt-foreign", path)
					}
					if err == nil {
						t.Cleanup(func() {
							if err := os.Rename(path, "/usr/local/lib/alinksec-apt-foreign"); err != nil {
								t.Error(err)
							}
						})
					}
				} else {
					err = os.Chown(path, 1000, 0)
				}
			case "access-acl":
				err = unix.Setxattr(path, "system.posix_acl_access", logACL(), 0)
			case "default-acl":
				err = unix.Setxattr(filepath.Dir(path), "system.posix_acl_default", logACL(), 0)
			case "too-large":
				err = os.WriteFile(path, []byte(strings.Repeat("#", 64*1024)+"\n"), 0644)
			case "unterminated":
				err = os.WriteFile(path, []byte("# comment"), 0644)
			case "selected-directory":
				err = os.Remove(path)
				if err == nil {
					err = os.Mkdir(path, 0755)
				}
			case "too-many-parts", "too-many-names":
				n := 34
				if kind == "too-many-names" {
					n = 129
				}
				for i := 0; i < n; i++ {
					err = os.WriteFile(filepath.Join(filepath.Dir(path), fmt.Sprintf("%03d-fixture", i)), nil, 0644)
					if err != nil {
						break
					}
				}
			case "malformed-irrelevant":
				err = os.WriteFile(path, []byte("DPkg::Pre-Install-Pkgs { \"unterminated\";\n"), 0644)
			case "unknown-boolean":
				err = os.WriteFile(path, []byte("APT::Get::AllowUnauthenticated \"flase\";\n"), 0644)
			case "include":
				err = os.WriteFile(path, []byte("#include \"/tmp/external\";\n"), 0644)
			case "redirect":
				err = os.WriteFile(path, []byte("Dir::Etc::Main \"elsewhere\";\n"), 0644)
			}
			if err != nil {
				if os.Getenv("ALINKSEC_APT_NATIVE_REQUIRED") != "true" && (kind == "uid" && err == unix.EPERM || (kind == "access-acl" || kind == "default-acl") && (err == unix.EINVAL || err == unix.EOPNOTSUPP)) {
					t.Skip("local fixture unavailable; mandatory isolated native container covers it")
				}
				t.Fatal(err)
			}
			if r := aptPolicyWithin(aptSpec(), root, aptProbe); !r.Error || r.Passed {
				t.Fatalf("accepted %s: %+v", kind, r)
			}
		})
	}
}
func TestAPTChangesAndOneDeadline(t *testing.T) {
	for _, kind := range []string{"content", "replacement", "main-created", "part-created", "ignored-name-created", "package", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			root := aptFixture(t, nil, map[string]string{"50-policy": "APT::Get::AllowUnauthenticated \"false\";\n"})
			calls := 0
			probe := func(ctx context.Context, _ int) ItemResult {
				calls++
				if calls == 2 {
					path := filepath.Join(root, "etc/apt/apt.conf.d/50-policy")
					var err error
					switch kind {
					case "content":
						err = os.WriteFile(path, []byte("APT::Get::AllowUnauthenticated \"true\";\n"), 0644)
					case "replacement":
						err = os.Rename(path, path+".bak")
						if err == nil {
							err = os.WriteFile(path, []byte("# empty\n"), 0644)
						}
					case "main-created":
						err = os.WriteFile(filepath.Join(root, "etc/apt/apt.conf"), nil, 0644)
					case "part-created":
						err = os.WriteFile(filepath.Join(filepath.Dir(path), "99-policy"), nil, 0644)
					case "ignored-name-created":
						err = os.WriteFile(filepath.Join(filepath.Dir(path), ".ignored"), nil, 0644)
					case "package":
						return ItemResult{Error: true, Message: "package changed"}
					case "timeout":
						<-ctx.Done()
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				return aptProbe(ctx, 0)
			}
			cs := aptSpec()
			cs.TimeoutMs = 100
			start := time.Now()
			r := aptPolicyWithin(cs, root, probe)
			if !r.Error || r.Passed || time.Since(start) > time.Second {
				t.Fatalf("change/deadline accepted: %+v", r)
			}
		})
	}
}
