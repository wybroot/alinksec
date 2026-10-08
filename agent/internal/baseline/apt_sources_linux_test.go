//go:build linux

package baseline

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sourceKey = "/usr/share/keyrings/example.gpg"
const sourceLine = "deb [signed-by=" + sourceKey + "] https://example.invalid/archive noble main\n"
const sourceStanza = "Types: deb deb-src\nURIs: https://example.invalid/archive\nSuites: noble\nComponents: main universe\nSigned-By: " + sourceKey + "\n"

type aptSourceCase struct {
	name, config, main                  string
	parts                               map[string]string
	passed, candidateError, nativeError bool
	// Native libapt meta-index fields. No acquire/transport/signature invocation.
	native          []string
	nativeErrorText string
}

func aptSourceCases() []aptSourceCase {
	safe := "https://example.invalid/archive/\tnoble\tunset\t" + sourceKey + "\tfalse\tfalse\tfalse"
	trusted := strings.Replace(safe, "\tunset\t", "\ttrue\t", 1)
	insecure := strings.TrimSuffix(safe, "false\tfalse\tfalse") + "true\tfalse\tfalse"
	return []aptSourceCase{
		{name: "one-line-explicit", main: sourceLine, passed: true, native: []string{safe}},
		{name: "deb822-multiple-types-components", parts: map[string]string{"ubuntu.sources": sourceStanza}, passed: true, native: []string{safe}},
		{name: "trusted-yes", main: strings.Replace(sourceLine, "[signed-by=", "[trusted=yes signed-by=", 1), native: []string{trusted}},
		{name: "trusted-no", main: strings.Replace(sourceLine, "[signed-by=", "[trusted=no signed-by=", 1), passed: true, native: []string{strings.Replace(safe, "\tunset\t", "\tfalse\t", 1)}},
		{name: "insecure-source", main: strings.Replace(sourceLine, "[signed-by=", "[allow-insecure=yes signed-by=", 1), native: []string{insecure}},
		{name: "weak-source", main: strings.Replace(sourceLine, "[signed-by=", "[allow-weak=1 signed-by=", 1), native: []string{strings.TrimSuffix(safe, "false\tfalse\tfalse") + "false\ttrue\tfalse"}},
		{name: "downgrade-source", main: strings.Replace(sourceLine, "[signed-by=", "[allow-downgrade-to-insecure=on signed-by=", 1), native: []string{strings.TrimSuffix(safe, "false\tfalse\tfalse") + "false\tfalse\ttrue"}},
		{name: "global-weak", main: sourceLine, config: "Acquire::AllowWeakRepositories \"true\";\n", native: []string{strings.TrimSuffix(safe, "false\tfalse\tfalse") + "false\ttrue\tfalse"}},
		{name: "global-downgrade", main: sourceLine, config: "Acquire::AllowDowngradeToInsecureRepositories \"true\";\n", native: []string{strings.TrimSuffix(safe, "false\tfalse\tfalse") + "false\tfalse\ttrue"}},
		{name: "global-insecure", main: sourceLine, config: "Acquire::AllowInsecureRepositories \"true\";\n", native: []string{insecure}},
		{name: "source-over-global", main: strings.Replace(sourceLine, "[signed-by=", "[allow-insecure=no signed-by=", 1), config: "Acquire::AllowInsecureRepositories \"true\";\n", native: []string{safe}},
		{name: "binary-get-insecure", main: sourceLine, config: "Binary::apt-get::Acquire::AllowInsecureRepositories \"true\";\n", native: []string{safe}},
		{name: "global-clear", main: sourceLine, config: "Acquire::AllowInsecureRepositories \"true\"; #clear Acquire::AllowInsecureRepositories;\n", passed: true, native: []string{safe}},
		{name: "explicit-source-false", main: strings.Replace(sourceLine, "[signed-by=", "[allow-insecure=no allow-weak=off allow-downgrade-to-insecure=0 signed-by=", 1), passed: true, native: []string{safe}},
		{name: "missing-signed-by", main: "deb https://example.invalid/archive noble main\n", native: []string{strings.Replace(safe, sourceKey, "", 1)}},
		{name: "fingerprint-global-keyring-fallback", main: strings.Replace(sourceLine, sourceKey, strings.Repeat("a", 40)+"!", 1), native: []string{strings.Replace(safe, sourceKey, strings.Repeat("A", 40)+"!", 1)}},
		{name: "keyring-and-fingerprint", main: strings.Replace(sourceLine, sourceKey, sourceKey+","+strings.Repeat("a", 40), 1), passed: true, native: []string{strings.Replace(safe, sourceKey, sourceKey+","+strings.Repeat("A", 40), 1)}},
		{name: "multiple-keyrings", parts: map[string]string{"keys.sources": strings.Replace(sourceStanza, sourceKey, sourceKey+" /etc/apt/keyrings/second.asc", 1)}, passed: true, native: []string{strings.Replace(safe, sourceKey, sourceKey+",/etc/apt/keyrings/second.asc", 1)}},
		{name: "multi-uri-suite-continuation", parts: map[string]string{"multi.sources": strings.Replace(strings.Replace(sourceStanza, "noble\n", "noble noble-updates\n", 1), "https://example.invalid/archive\n", "https://example.invalid/archive\n https://mirror.invalid/archive\n", 1)}, passed: true, native: []string{safe, strings.Replace(safe, "\tnoble\t", "\tnoble-updates\t", 1), strings.Replace(safe, "example.invalid", "mirror.invalid", 1), strings.Replace(strings.Replace(safe, "example.invalid", "mirror.invalid", 1), "\tnoble\t", "\tnoble-updates\t", 1)}},
		{name: "disabled-stanza", main: sourceLine, parts: map[string]string{"disabled.sources": "Enabled: no\nTypes: deb\nURIs: malformed\nSigned-By: /missing.gpg\n"}, passed: true, native: []string{safe}},
		{name: "no-active-sources", parts: map[string]string{"disabled.sources": "Enabled: no\nTypes: deb\n"}},
		{name: "disabled-missing-type", parts: map[string]string{"disabled.sources": "Enabled: no\n"}, candidateError: true, nativeError: true, nativeErrorText: "Malformed stanza"},
		{name: "disabled-unknown-type", parts: map[string]string{"disabled.sources": "Types: unknown\nEnabled: no\n"}, candidateError: true, nativeError: true, nativeErrorText: "Type 'unknown' is not known"},
		{name: "filename-selection", main: sourceLine, parts: map[string]string{".hidden.list": "deb [trusted=yes] https://ignored.invalid/ noble main\n", "not-a-source.conf": "garbage\n", "unsafe.LIST": "garbage\n", "unsafe~.list": "garbage\n", "noextension": "garbage\n", "colon:valid.sources": sourceStanza}, passed: true, native: []string{safe}},
		{name: "same-release-consistent", main: sourceLine + strings.Replace(sourceLine, "deb ", "deb-src ", 1), passed: true, native: []string{safe}},
		{name: "conflicting-keyrings", main: sourceLine + strings.Replace(sourceLine, sourceKey, "/etc/apt/keyrings/second.asc", 1), candidateError: true, nativeError: true},
		{name: "normalized-port-conflict", main: strings.Replace(sourceLine, "example.invalid/", "example.invalid:0443/", 1) + strings.Replace(strings.Replace(sourceLine, "example.invalid/", "example.invalid:443/", 1), sourceKey, "/etc/apt/keyrings/second.asc", 1), candidateError: true, nativeError: true},
		{name: "conflicting-trusted", main: strings.Replace(sourceLine, "[signed-by=", "[trusted=yes signed-by=", 1) + strings.Replace(sourceLine, "[signed-by=", "[trusted=no signed-by=", 1), candidateError: true, nativeError: true},
		{name: "deb822-ignored-insecure-field", parts: map[string]string{"ignored.sources": sourceStanza + "Allow-Insecure: yes\n"}, candidateError: true, native: []string{safe}},
		{name: "deb822-ignored-weak-field", parts: map[string]string{"ignored.sources": sourceStanza + "Allow-Weak: yes\n"}, candidateError: true, native: []string{safe}},
		{name: "deb822-ignored-downgrade-field", parts: map[string]string{"ignored.sources": sourceStanza + "Allow-Downgrade-To-Insecure: yes\n"}, candidateError: true, native: []string{safe}},
		{name: "unknown-list-option", main: strings.Replace(sourceLine, "[signed-by=", "[unknown=yes signed-by=", 1), candidateError: true, native: []string{safe}},
	}
}
func aptSourcesFixture(t *testing.T, c aptSourceCase) string {
	t.Helper()
	root := aptFixture(t, &c.config, nil)
	for _, dir := range []string{"etc/apt/sources.list.d", "usr/share/keyrings", "etc/apt/keyrings"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Deliberately NOT valid keys. The candidate only checks declarations and
	// metadata. Native parsing also does not verify key contents or signatures.
	for _, key := range []string{sourceKey, "/etc/apt/keyrings/second.asc"} {
		if err := os.WriteFile(filepath.Join(root, key), []byte("not cryptographic key material\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if c.main != "" {
		if err := os.WriteFile(filepath.Join(root, "etc/apt/sources.list"), []byte(c.main), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range c.parts {
		if err := os.WriteFile(filepath.Join(root, "etc/apt/sources.list.d", name), []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestAPTSourcesPolicyCases(t *testing.T) {
	for _, c := range aptSourceCases() {
		t.Run(c.name, func(t *testing.T) {
			root := aptSourcesFixture(t, c)
			r := aptPolicyWithin(aptSourcesSpec(), root, aptProbe)
			if r.Error != c.candidateError || r.Passed != c.passed {
				t.Fatalf("policy %+v", r)
			}
			for _, word := range []string{"key_identity_state=unverified", "key_material_state=unverified", "repository_signature_state=unverified"} {
				if !strings.Contains(r.Actual, word) {
					t.Fatalf("missing %s: %+v", word, r)
				}
			}
		})
	}
}
func TestAPTSourcesUnsupportedSyntax(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(sourceLine, "[signed-by=", "[Trusted=yes signed-by=", 1),
		strings.Replace(sourceLine, "[signed-by=", "[trusted=maybe signed-by=", 1),
		strings.Replace(sourceLine, sourceKey, "/tmp/key.gpg", 1),
		strings.Replace(sourceLine, sourceKey, sourceKey+","+sourceKey, 1),
		strings.Replace(sourceLine, "noble main", "noble/ main", 1),
		strings.Replace(sourceLine, "https://", "https://user:password@", 1),
		strings.Replace(sourceLine, "noble", "$(ARCH)", 1),
		sourceStanza + "Signed-By: " + sourceKey + "\n", sourceStanza + "Unknown: yes\n",
		strings.Replace(sourceStanza, "Signed-By: "+sourceKey, "Signed-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----", 1),
		strings.Replace(sourceStanza, "Types: deb deb-src", "Types: unknown", 1),
		" URIs: https://example.invalid\n", sourceStanza + "Enabled: maybe\n",
	} {
		s := aptSources{}
		if err := s.parse(raw, strings.HasPrefix(raw, "Types:") || strings.HasPrefix(raw, " URIs:")); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, config := range []string{"Dir::Etc::sourcelist \"other\";\n", "#clear Dir::Etc::sourcelist;\n", "#clear APT::Sources;\n", "Binary::apt::APT::Sources::With { \"elsewhere\"; };\n", "Acquire::AllowWeakRepositories { \"false\"; };\n", "Acquire::AllowWeakRepositories \"maybe\";\n"} {
		root := aptSourcesFixture(t, aptSourceCase{main: sourceLine, config: config})
		if r := aptPolicyWithin(aptSourcesSpec(), root, aptProbe); !r.Error || r.Passed {
			t.Fatalf("accepted config %q: %+v", config, r)
		}
	}
}
func TestAPTSourcesUnsafeInputs(t *testing.T) {
	for _, target := range []string{"etc/apt/sources.list", "usr/share/keyrings/example.gpg"} {
		for _, kind := range []string{"symlink", "hardlink", "fifo", "writable", "access-acl", "empty-key", "missing", "not-readable", "uid"} {
			t.Run(target+"/"+kind, func(t *testing.T) {
				root := aptSourcesFixture(t, aptSourceCase{main: sourceLine})
				p := filepath.Join(root, target)
				var err error
				switch kind {
				case "symlink":
					err = os.Rename(p, p+".old")
					if err == nil {
						err = os.Symlink(p+".old", p)
					}
				case "hardlink":
					err = os.Link(p, p+".old")
				case "fifo":
					err = os.Remove(p)
					if err == nil {
						err = unix.Mkfifo(p, 0600)
					}
				case "writable":
					err = os.Chmod(p, 0666)
				case "access-acl":
					err = unix.Setxattr(p, "system.posix_acl_access", logACL(), 0)
				case "empty-key":
					if !strings.HasSuffix(p, ".gpg") {
						return
					}
					err = os.WriteFile(p, nil, 0644)
				case "missing":
					err = os.Remove(p)
				case "not-readable":
					if !strings.HasSuffix(p, ".gpg") {
						return
					}
					err = os.Chmod(p, 0600)
				case "uid":
					if os.Getenv("ALINKSEC_APT_NATIVE_REQUIRED") == "true" {
						err = os.Remove(p)
						if err == nil {
							err = os.Rename("/usr/local/lib/alinksec-apt-foreign", p)
						}
						if err == nil {
							t.Cleanup(func() {
								if err := os.Rename(p, "/usr/local/lib/alinksec-apt-foreign"); err != nil {
									t.Error(err)
								}
							})
						}
					} else {
						err = os.Chown(p, 1000, 0)
					}
				}
				if err != nil {
					if os.Getenv("ALINKSEC_APT_NATIVE_REQUIRED") != "true" && (kind == "access-acl" && (err == unix.EINVAL || err == unix.EOPNOTSUPP) || kind == "uid" && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL))) {
						t.Skip("local fixture unavailable; mandatory native coverage")
					}
					t.Fatal(err)
				}
				r := aptPolicyWithin(aptSourcesSpec(), root, aptProbe)
				// Missing main source list has native empty-source defaults => fail, not error.
				wantError := !(target == "etc/apt/sources.list" && kind == "missing")
				if r.Error != wantError || r.Passed {
					t.Fatalf("accepted unsafe input: %+v", r)
				}
			})
		}
	}
	for _, dir := range []string{"etc/apt/sources.list.d", "usr/share/keyrings", "etc/apt/keyrings"} {
		t.Run(dir+"-default-acl", func(t *testing.T) {
			root := aptSourcesFixture(t, aptSourceCase{main: strings.Replace(sourceLine, sourceKey, "/etc/apt/keyrings/second.asc", 1)})
			if dir == "usr/share/keyrings" {
				if err := os.WriteFile(filepath.Join(root, "etc/apt/sources.list"), []byte(sourceLine), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err := unix.Setxattr(filepath.Join(root, dir), "system.posix_acl_default", logACL(), 0)
			if err != nil {
				if os.Getenv("ALINKSEC_APT_NATIVE_REQUIRED") != "true" && (err == unix.EINVAL || err == unix.EOPNOTSUPP) {
					t.Skip("mandatory native ACL coverage")
				}
				t.Fatal(err)
			}
			if r := aptPolicyWithin(aptSourcesSpec(), root, aptProbe); !r.Error || r.Passed {
				t.Fatalf("accepted directory ACL: %+v", r)
			}
		})
	}
}
func TestAPTSourcesChangesAndLimits(t *testing.T) {
	for _, kind := range []string{"source", "key", "new-source", "main-created", "ignored-name", "timeout", "package", "too-many-sources", "too-many-releases", "too-many-names"} {
		t.Run(kind, func(t *testing.T) {
			c := aptSourceCase{main: sourceLine}
			if kind == "main-created" {
				c.main = ""
				c.parts = map[string]string{"50-source.list": sourceLine}
			}
			root := aptSourcesFixture(t, c)
			switch kind {
			case "too-many-sources", "too-many-names":
				n := 33
				if kind == "too-many-names" {
					n = 129
				}
				for i := 0; i < n; i++ {
					name := fmt.Sprintf("%03d.list", i)
					if err := os.WriteFile(filepath.Join(root, "etc/apt/sources.list.d", name), []byte(sourceLine), 0644); err != nil {
						t.Fatal(err)
					}
				}
			case "too-many-releases":
				var b strings.Builder
				for i := 0; i < 65; i++ {
					b.WriteString(strings.Replace(sourceLine, "noble", fmt.Sprintf("suite%d", i), 1))
				}
				if err := os.WriteFile(filepath.Join(root, "etc/apt/sources.list"), []byte(b.String()), 0644); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			probe := func(ctx context.Context, _ int) ItemResult {
				calls++
				if calls == 2 {
					var err error
					switch kind {
					case "source":
						err = os.WriteFile(filepath.Join(root, "etc/apt/sources.list"), []byte(strings.Replace(sourceLine, "noble", "other", 1)), 0644)
					case "key":
						err = os.WriteFile(filepath.Join(root, sourceKey), []byte("changed material\n"), 0644)
					case "new-source", "ignored-name":
						name := "99-new.list"
						if kind == "ignored-name" {
							name = ".hidden.list"
						}
						err = os.WriteFile(filepath.Join(root, "etc/apt/sources.list.d", name), []byte(sourceLine), 0644)
					case "main-created":
						err = os.WriteFile(filepath.Join(root, "etc/apt/sources.list"), []byte(sourceLine), 0644)
					case "timeout":
						<-ctx.Done()
					case "package":
						return ItemResult{Error: true, Message: "package changed"}
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				return aptProbe(ctx, 0)
			}
			cs := aptSourcesSpec()
			cs.TimeoutMs = 50
			start := time.Now()
			if r := aptPolicyWithin(cs, root, probe); !r.Error || r.Passed || time.Since(start) > time.Second {
				t.Fatalf("accepted change/limit: %+v", r)
			}
		})
	}
}
