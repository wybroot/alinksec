//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeSudoersDeclarations(t *testing.T) {
	if os.Getenv("ALINKSEC_SUDOERS_NATIVE_REQUIRED") != "true" {
		t.Skip("disposable exact sudo package container only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-sudoers-fixture")
	status, statusErr := os.ReadFile("/proc/self/status")
	if _, dockerErr := os.Stat("/.dockerenv"); dockerErr != nil || err != nil || string(marker) != "isolated-sudoers-declarations-v1\n" || statusErr != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000\n") || os.Geteuid() != 0 {
		t.Fatal("isolated root Docker fixture without capabilities required")
	}
	// Native utilities are restricted to this throwaway container, with no debug
	// configuration. Production never loads sudo.conf or calls these utilities.
	if err := os.WriteFile("/etc/sudo.conf", nil, 0644); err != nil {
		t.Fatal(err)
	}
	for _, option := range []string{"authentication", "allowed_logging"} {
		spec := sudoersSpec(option)
		spec.TimeoutMs = 5000
		r := checkSudoers(spec)
		if r.Error || r.Passed {
			t.Fatalf("vendor defaults lack explicit reference declarations: %+v", r)
		}
		t.Logf("vendor disk policy (no authentication/authorization/delivery proof): %s", r.Actual)
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/sudoers/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var candidate struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &candidate); err != nil || len(candidate.Items) != 2 {
		t.Fatalf("candidate: %v", err)
	}
	var specs []*CheckSpec
	for _, item := range candidate.Items {
		cs, err := ParseCheck(string(item.Check))
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, cs)
	}
	cvt := "/usr/bin/cvtsudoers"
	for _, c := range sudoersCases() {
		t.Run(c.name, func(t *testing.T) {
			root := sudoersFixture(t, c.main, c.includes)
			path := filepath.Join(root, "etc/sudoers")
			// Native reads the same private include graph at its real filesystem paths.
			native := strings.ReplaceAll(c.main, "/etc/sudoers.d", filepath.Join(root, "etc/sudoers.d"))
			nativePath := filepath.Join(root, "native-sudoers")
			if err := os.WriteFile(nativePath, []byte(native), 0644); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "/usr/sbin/visudo", "-c", "-f", nativePath).CombinedOutput()
			if err != nil {
				t.Fatalf("native syntax %v: %s", err, out)
			}
			cmd := exec.CommandContext(ctx, cvt, "-c", "", "-i", "sudoers", "-f", "json", nativePath)
			cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("native conversion: %v", err)
			}
			var parsed struct {
				Defaults []struct{ Options []map[string]any } `json:"Defaults"`
				Users    []struct {
					Commands []struct {
						Options  []map[string]any
						Commands []any
					} `json:"Cmnd_Specs"`
				} `json:"User_Specs"`
			}
			if err := json.Unmarshal(output, &parsed); err != nil {
				t.Fatal(err)
			}
			authenticate, logAllowed := false, false
			exempt, logfile := "", ""
			for _, d := range parsed.Defaults {
				for _, o := range d.Options {
					for name, value := range o {
						switch name {
						case "authenticate":
							authenticate = value == true
						case "log_allowed":
							logAllowed = value == true
						case "exempt_group":
							exempt = ""
							if s, ok := value.(string); ok {
								exempt = s
							}
						case "logfile":
							logfile = ""
							if s, ok := value.(string); ok {
								logfile = s
							}
						}
					}
				}
			}
			commands, nopasswd := 0, 0
			for _, u := range parsed.Users {
				for _, group := range u.Commands {
					noauth := false
					for _, o := range group.Options {
						if v, ok := o["authenticate"]; ok {
							noauth = v == false
						}
					}
					commands += len(group.Commands)
					if noauth {
						nopasswd += len(group.Commands)
					}
				}
			}
			nativeAuth := authenticate && exempt == "" && nopasswd == 0 && commands > 0
			nativeLogging := logAllowed && logfile == "/var/log/sudo.log" && commands > 0
			if nativeAuth != c.auth || nativeLogging != c.logging || nopasswd != c.nopasswd || commands != c.commands {
				t.Fatalf("native AST reference mismatch auth=%t log=%t nopasswd=%d commands=%d JSON=%s", nativeAuth, nativeLogging, nopasswd, commands, output)
			}
			for _, cs := range specs {
				r := sudoersWithin(cs, root, sudoPackage)
				want := nativeAuth
				if cs.Option == "allowed_logging" {
					want = nativeLogging
				}
				if r.Error || r.Passed != want {
					t.Fatalf("native/reference mismatch: %+v path=%s", r, path)
				}
				t.Logf("native parsed declaration comparison (private fixture): %s", r.Actual)
			}
		})
	}
}
