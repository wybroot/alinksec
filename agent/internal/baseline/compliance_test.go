package baseline

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func compliancePack(t *testing.T, level string) []*pb.BaselineCheckSpec {
	t.Helper()
	platform := "linux"
	if runtime.GOOS == "windows" {
		platform = "windows"
	}
	data, err := os.ReadFile(filepath.Join("../../../deploy/baseline/packages/compliance/level"+level, platform+"-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct {
			Code  string
			Check json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var specs []*pb.BaselineCheckSpec
	for _, item := range doc.Items {
		specs = append(specs, &pb.BaselineCheckSpec{ItemId: item.Code, Check: string(item.Check)})
	}
	return specs
}

func TestCompliancePacksUseSupportedChecksOnTheirNativePlatform(t *testing.T) {
	data, err := os.ReadFile("../../../deploy/baseline/compliance/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct{ WindowsReferences map[string]string }
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(catalog.WindowsReferences, windowsSecurityReferences) {
		t.Fatal("server/Agent Windows policy reference drift")
	}
	if runtime.GOOS == "windows" && !isApprovedCmdOutput(windowsSMB1Query) {
		t.Fatal("SMB feature query is not compiled into the allowlist")
	}
	for _, level := range []string{"2", "3"} {
		for _, item := range compliancePack(t, level) {
			if _, err := ParseCheck(item.Check); err != nil {
				t.Errorf("level %s %s: %v", level, item.ItemId, err)
			}
		}
	}
	for option, ref := range windowsSecurityReferences {
		s := map[string]any{"type": "windows_security_policy", "target": "local-machine", "option": option, "operator": "eq", "expected": ref}
		for _, mutation := range []string{"reference", "target", "command", "timeout", "unknown"} {
			copy := map[string]any{}
			for k, v := range s {
				copy[k] = v
			}
			switch mutation {
			case "reference":
				copy["expected"] = "anything"
			case "target":
				copy["target"] = "remote-machine"
			case "command":
				copy["cmd"] = "whoami"
			case "timeout":
				copy["timeout_ms"] = 0
			case "unknown":
				copy["option"] = "unreviewed"
			}
			data, _ := json.Marshal(copy)
			if _, err := ParseCheck(string(data)); err == nil {
				t.Errorf("accepted %s %s", option, mutation)
			}
		}
	}
}

func TestNativeCompliancePack(t *testing.T) {
	output := os.Getenv("ALINKSEC_COMPLIANCE_NATIVE_OUTPUT")
	if output == "" {
		t.Skip("native evidence capture not requested")
	}
	items := compliancePack(t, "3")
	result := Run("native-compliance", items, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(result.Items) != len(items) {
		t.Fatal("incomplete native report")
	}
	counts := map[string]int{"pass": 0, "fail": 0, "error": 0}
	for _, item := range result.Items {
		if _, ok := counts[item.ExecutionStatus]; !ok {
			t.Fatal("unknown execution outcome")
		}
		counts[item.ExecutionStatus]++
		if item.Passed != (item.ExecutionStatus == "pass") {
			t.Fatal("inconsistent pass flag")
		}
		// Native SAM observations are available on the Windows CI host, without
		// changing its security policy. Other missing features remain errors.
		if runtime.GOOS == "windows" && (item.ItemId == "MLPS-WIN-password_length" || item.ItemId == "MLPS-WIN-password_age" || item.ItemId == "MLPS-WIN-password_history" || item.ItemId == "MLPS-WIN-lockout") && item.ExecutionStatus == "error" {
			t.Errorf("SAM policy unavailable: %s", item.Message)
		}
	}
	evidence := map[string]any{"contract": 1, "os": runtime.GOOS, "arch": runtime.GOARCH, "scope": "GB/T 22239-2019 level 2/3 host automatic evidence only", "total": len(items), "counts": counts, "result": result}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("native compliance evidence: %s (%v)", output, counts)
}
