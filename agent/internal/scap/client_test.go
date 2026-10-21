package scap

import (
	"context"
	"encoding/json"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNativeEnvironmentKeepsIdentityWithoutModuleInjection(t *testing.T) {
	t.Setenv("PERL5LIB", "untrusted-parent-modules")
	t.Setenv("PERL5OPT", "-Muntrusted")
	t.Setenv("ALINKSEC_SECRET", "parent-secret")
	t.Setenv("USERNAME", "service-user")
	t.Setenv("USERDOMAIN", "service-domain")
	t.Setenv("COMPUTERNAME", "service-host")
	t.Setenv("USERPROFILE", `C:\Users\service-user`)
	env := map[string]string{}
	for _, entry := range cleanEnvironment() {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	for _, key := range []string{"PERL5LIB", "PERL5OPT", "ALINKSEC_SECRET"} {
		if _, exists := env[key]; exists {
			t.Fatal("parent injection entered native runtime", key)
		}
	}
	if runtime.GOOS == "windows" {
		if env["LANG"] != "C" || env["USERNAME"] != "service-user" || env["USERDOMAIN"] != "service-domain" || env["COMPUTERNAME"] != "service-host" || env["USERPROFILE"] != `C:\Users\service-user` {
			t.Fatal("Windows native identity environment missing")
		}
	}
}

func TestDisabledAndInvalidCommandsNeverProduceSuccessfulEvidence(t *testing.T) {
	client := New(Config{}, t.TempDir())
	report := client.Scan(context.Background(), "command", &pb.CmdScapScan{TaskId: "task", ExecutionContract: 1})
	if report.State != "failed" || report.Issue != "scap_disabled" || len(report.Rules) != 0 || len(report.Scores) != 0 || report.SourceResultSha256 != "" {
		t.Fatal("disabled engine fabricated evidence", report)
	}
	cfg := Config{Enabled: true, RuntimeDir: t.TempDir(), RuntimeSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	client = New(cfg, t.TempDir())
	report = client.Scan(context.Background(), "command", &pb.CmdScapScan{TaskId: "task", ExecutionContract: 1, RuntimeSha256: cfg.RuntimeSHA256})
	if report.State != "failed" || report.Issue != "scap_command_invalid" || len(report.Rules) != 0 {
		t.Fatal("invalid command ran", report)
	}
	if client.Status().State == "ready" {
		t.Fatal("configuration presence treated as native identity proof")
	}
}

func TestRuntimeCloneChecksEveryModuleAndRejectsUnlistedFiles(t *testing.T) {
	if Contract() != 1 {
		t.Skip("unsupported platform")
	}
	root := t.TempDir()
	executable := "cscc"
	if filepath.Separator == '\\' {
		executable = "cscc.exe"
	}
	files := map[string][]byte{executable: []byte("trusted launcher"), "options.xml": []byte("<options/>"), "lib/module.pm": []byte("trusted module"), "lib64/libstdc++-6.dll": []byte("pinned native library")}
	manifest := runtimeManifest{SchemaVersion: 1, Engine: "SCC", Version: "5.15", Platform: runtime.GOOS + "-" + runtime.GOARCH, Executable: executable}
	for name, data := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, runtimeFile{Path: name, Size: int64(len(data)), SHA256: Digest(data)})
	}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(root, "alinksec-runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unapproved.pm"), []byte("injected module"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Enabled: true, RuntimeDir: root, RuntimeSHA256: Digest(data)}
	destination := filepath.Join(t.TempDir(), "runtime")
	if _, err := cloneRuntime(context.Background(), cfg, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "unapproved.pm")); !os.IsNotExist(err) {
		t.Fatal("unlisted module entered executable directory")
	}
	if err := os.WriteFile(filepath.Join(root, "lib", "module.pm"), []byte("changed module"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cloneRuntime(context.Background(), cfg, filepath.Join(t.TempDir(), "runtime")); Code(err) != "scap_runtime_changed" {
		t.Fatal("module tampering accepted", err)
	}
	cfg.RuntimeSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := cloneRuntime(context.Background(), cfg, filepath.Join(t.TempDir(), "runtime")); Code(err) != "scap_runtime_changed" {
		t.Fatal("manifest tampering accepted", err)
	}
}
