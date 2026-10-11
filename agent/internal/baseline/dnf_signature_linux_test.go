//go:build linux

package baseline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dnfMainFixture = "[main]\ngpgcheck=1\nrepo_gpgcheck=1\nlocalpkg_gpgcheck=1\n"

func dnfFixture(t *testing.T) string {
	root := t.TempDir()
	for _, path := range []string{"etc/dnf", "etc/yum.repos.d", "etc/yum/repos.d", "etc/distro.repos.d"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	pamWrite(t, filepath.Join(root, "etc/dnf/dnf.conf"), dnfMainFixture)
	pamWrite(t, filepath.Join(root, "etc/yum.repos.d/test.repo"), "[test]\nname=PRIVATE_REPO\nbaseurl=https://PRIVATE_REPO\nenabled=1\n")
	return root
}
func TestDNFSignatureInheritanceAndFailureStates(t *testing.T) {
	for _, kind := range []string{"inherited", "override_false", "disabled_false", "main_false", "local_false", "default_false", "empty", "additional_dir", "missing", "symlink", "writable", "duplicate_id", "duplicate_key", "include", "variable", "version", "version_change", "cancel", "reposdir"} {
		t.Run(kind, func(t *testing.T) {
			root := dnfFixture(t)
			main := filepath.Join(root, "etc/dnf/dnf.conf")
			repo := filepath.Join(root, "etc/yum.repos.d/test.repo")
			pass, executionError := kind == "inherited", true
			for _, known := range []string{"inherited", "override_false", "disabled_false", "main_false", "local_false", "default_false", "empty", "additional_dir"} {
				if kind == known {
					executionError = false
				}
			}
			query := func(context.Context) (string, error) { return "4.14.0", nil }
			switch kind {
			case "override_false":
				pamWrite(t, repo, "[test]\ngpgcheck=0\n")
			case "disabled_false":
				pamWrite(t, repo, "[test]\nenabled=0\nrepo_gpgcheck=0\n")
			case "main_false":
				pamWrite(t, main, "[main]\ngpgcheck=0\nrepo_gpgcheck=1\nlocalpkg_gpgcheck=1\n")
			case "local_false":
				pamWrite(t, main, "[main]\ngpgcheck=1\nrepo_gpgcheck=1\nlocalpkg_gpgcheck=0\n")
			case "default_false":
				pamWrite(t, main, "[main]\n")
			case "empty":
				os.Remove(repo)
			case "additional_dir":
				pamWrite(t, filepath.Join(root, "etc/distro.repos.d/extra.repo"), "[extra]\ngpgcheck=0\n")
			case "missing":
				os.Remove(main)
			case "symlink":
				os.Remove(repo)
				os.Symlink(main, repo)
			case "writable":
				os.Chmod(repo, 0666)
			case "duplicate_id":
				pamWrite(t, filepath.Join(root, "etc/yum/repos.d/extra.repo"), "[test]\ngpgcheck=1\n")
			case "duplicate_key":
				pamWrite(t, repo, "[test]\ngpgcheck=1\ngpgcheck=0\n")
			case "include":
				pamWrite(t, main, dnfMainFixture+"include=/PRIVATE_REPO\n")
			case "variable":
				pamWrite(t, repo, "[test]\ngpgcheck=$PRIVATE_REPO\n")
			case "version":
				query = func(context.Context) (string, error) { return "4.18.0", nil }
			case "version_change":
				calls := 0
				query = func(context.Context) (string, error) {
					calls++
					if calls == 2 {
						return "4.14.1", nil
					}
					return "4.14.0", nil
				}
			case "cancel":
				query = func(ctx context.Context) (string, error) { <-ctx.Done(); return "", ctx.Err() }
			case "reposdir":
				pamWrite(t, main, dnfMainFixture+"reposdir=/PRIVATE_REPO\n")
			}
			r := dnfSignatureWithin(dnfSpec(), root, query, uint32(os.Geteuid()), uint32(os.Getegid()))
			if r.Passed != pass || r.Error != executionError || strings.Contains(r.Actual+r.Message, "PRIVATE_REPO") {
				t.Fatal(r)
			}
		})
	}
}

func TestDNFSignatureGrammarAndLimits(t *testing.T) {
	for _, raw := range []string{"gpgcheck=1\n", "[bad$]\ngpgcheck=1\n", "[x]\ngpgcheck=1\ngpgcheck=0\n", "[x]\ninclude=foo\n", "[x]\n" + strings.Repeat("x", 4097), strings.Repeat("\n", 1025)} {
		if _, err := parseDNFDeclarations([]byte(raw)); err == nil {
			t.Fatal("ambiguous INI accepted")
		}
	}
	root := dnfFixture(t)
	pamWrite(t, filepath.Join(root, "etc/dnf/dnf.conf"), dnfMainFixture+"reposdir=/etc/yum.repos.d, /etc/yum/repos.d /etc/distro.repos.d\n")
	r := dnfSignatureWithin(dnfSpec(), root, func(context.Context) (string, error) { return "4.14.0", nil }, uint32(os.Geteuid()), uint32(os.Getegid()))
	if r.Error || !r.Passed {
		t.Fatal(r)
	}
}
