package baseline

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

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
