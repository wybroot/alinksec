package baseline

import (
	"encoding/json"
	"google.golang.org/protobuf/proto"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestRunPreservesCheckIDs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(file, []byte("setting=yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	specs := []CheckSpec{
		{Type: "file_content", Target: file, Regex: "^setting=yes$"},
		{Type: "file_line", Target: file, Operator: "contains", Expected: "absent"},
		{Type: "file_perm", Target: filepath.Join(t.TempDir(), "missing")},
		{Type: "cmd_output", Cmd: "echo unapproved", Operator: "eq", Expected: "unapproved"},
		{Type: "invalid"},
	}
	var checks []*pb.BaselineCheckSpec
	for i, spec := range specs {
		data, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		checks = append(checks, &pb.BaselineCheckSpec{ItemId: string(rune('A' + i)), Check: string(data)})
	}
	result := Run("test-task", checks, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if result.GetTaskId() != "test-task" || len(result.GetItems()) != len(checks) {
		t.Fatalf("unexpected task result: %v", result)
	}
	for i, item := range result.GetItems() {
		if item.GetItemId() != checks[i].GetItemId() {
			t.Errorf("check %d ID = %q, want %q", i, item.GetItemId(), checks[i].GetItemId())
		}
		if item.GetPassed() != (i == 0) {
			t.Errorf("check %d passed = %v", i, item.GetPassed())
		}
		want := "error"
		if i == 0 {
			want = "pass"
		} else if i == 1 || i == 2 && runtime.GOOS == "linux" {
			want = "fail"
		}
		if item.GetExecutionStatus() != want {
			t.Errorf("check %d status=%s, want %s", i, item.GetExecutionStatus(), want)
		}
	}
}

func TestRunPreservesProductDeclarationIDs(t *testing.T) {
	// Product/version rejection is still a report for the dispatched item.
	// These checks previously returned before the common item-ID assignment.
	specs := []*CheckSpec{aptSpec(), aptSourcesSpec(), {Type: "sudoers_policy", Target: "/etc/sudoers", Option: "authentication", Operator: "eq", Expected: sudoersReference("authentication"), TimeoutMs: 100}}
	var checks []*pb.BaselineCheckSpec
	for _, cs := range specs {
		cs.TimeoutMs = 100
		definition := map[string]any{"type": cs.Type, "target": cs.Target, "operator": cs.Operator, "expected": cs.Expected, "timeout_ms": cs.TimeoutMs}
		if cs.Option != "" {
			definition["option"] = cs.Option
		}
		raw, err := json.Marshal(definition)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseCheck(string(raw)); err != nil {
			t.Fatal(err)
		}
		checks = append(checks, &pb.BaselineCheckSpec{ItemId: cs.Type, Check: string(raw)})
	}
	r := Run("product-declarations", checks, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(r.Items) != len(checks) {
		t.Fatalf("incomplete product reports: %+v", r)
	}
	for i, item := range r.Items {
		if item.ItemId != checks[i].ItemId {
			t.Fatalf("lost dispatched item ID: %+v", item)
		}
	}
}

func TestLargeEvidenceIsValidAndFitsOneGRPCReport(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(file, []byte(strings.Repeat("安", 5000)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(CheckSpec{Type: "file_content", Target: file, Regex: "^安"})
	specs := make([]*pb.BaselineCheckSpec, MaxChecks)
	for i := range specs {
		specs[i] = &pb.BaselineCheckSpec{ItemId: "test", Check: string(data)}
	}
	result := Run("bounded", specs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, item := range result.Items {
		if !item.Passed || item.ExecutionStatus != "pass" || !utf8.ValidString(item.Actual) || len(item.Actual) > 2051 {
			t.Fatalf("unbounded or invalid evidence: %d", len(item.Actual))
		}
	}
	wire, err := proto.Marshal(result)
	if err != nil || len(wire) > 4*1024*1024 {
		t.Fatalf("report bytes=%d, err=%v", len(wire), err)
	}
}

func TestParserRejectsUnboundedTimeoutAndUnknownFields(t *testing.T) {
	for _, data := range []string{
		`{"type":"cmd_output","cmd":"sysctl -n net.ipv4.ip_forward","timeout_ms":-1}`,
		`{"type":"cmd_output","cmd":"sysctl -n net.ipv4.ip_forward","timeout_ms":30001}`,
		`{"type":"file_line","target":"relative","operator":"contains","expected":"x"}`,
		`{"type":"cmd_output","arbitrary_script":"x"}`,
		`{"type":"cmd_output"} {}`,
		`{"type":"cmd_output","type":"file_line"}`,
		`{"type":"file_content","target":"/etc/test","regex":""}`,
		`{"type":"file_line","target":"/etc/test","operator":"not_contains","expected":""}`,
		`{"type":"file_perm","target":"/etc/test","perm":"8888"}`,
	} {
		if _, err := ParseCheck(data); err == nil {
			t.Fatalf("accepted invalid check: %s", data)
		}
	}
}

func TestParserAcceptsUnicodeWithinTheServerCharacterLimit(t *testing.T) {
	data, _ := json.Marshal(CheckSpec{Type: "file_line", Target: filepath.Join(t.TempDir(), "设置"), Operator: "contains", Expected: strings.Repeat("安", 1000)})
	if _, err := ParseCheck(string(data)); err != nil {
		t.Fatalf("valid Unicode check rejected: %v", err)
	}
}

func TestEvaluateNumericOutput(t *testing.T) {
	for _, tc := range []struct {
		operator, actual, expected string
		passed                     bool
	}{
		{"gt", "1", "0", true},
		{"gt", "0", "0", false},
		{"gte", "2", "2", true},
		{"lt", "-1.5", "0", true},
		{"lte", "2", "1", false},
		{"gt", "error\n1", "0", false},
		{"gt", "1", "invalid", false},
		{"gt", "NaN", "0", false},
		{"gt", "+Inf", "0", false},
	} {
		t.Run(tc.operator+"/"+tc.actual+"/"+tc.expected, func(t *testing.T) {
			result := evaluateOutput(tc.actual, &CheckSpec{Operator: tc.operator, Expected: tc.expected})
			if result.Passed != tc.passed || result.Actual != tc.actual {
				t.Fatalf("result = %+v, want passed=%v, actual=%q", result, tc.passed, tc.actual)
			}
		})
	}
}
