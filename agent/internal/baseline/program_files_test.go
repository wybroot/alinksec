package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func programReferenceExpected(raw string) string {
	return "scope=/usr/bin+/usr/sbin,sha256=" + fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) + ",exact=mode/uid/gid/content"
}
func programFilesSpec(option string) CheckSpec {
	expected := linkerMetadataReference
	if option == "privileged_reference" {
		expected = programReferenceExpected(privilegedReferenceHeader)
	}
	return CheckSpec{Type: "linux_program_files", Target: "system-program-inputs", Option: option, Operator: "eq", Expected: expected, TimeoutMs: 1000}
}
func programFilesJSON(s CheckSpec) string {
	raw, _ := json.Marshal(map[string]any{"type": s.Type, "target": s.Target, "option": s.Option, "operator": s.Operator, "expected": s.Expected, "timeout_ms": s.TimeoutMs})
	return string(raw)
}
func TestProgramFilesDefinitionBoundary(t *testing.T) {
	for _, option := range []string{"linker_metadata", "privileged_reference"} {
		s := programFilesSpec(option)
		if _, err := ParseCheck(programFilesJSON(s)); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*CheckSpec){func(s *CheckSpec) { s.Target = "/tmp" }, func(s *CheckSpec) { s.Option = "execute" }, func(s *CheckSpec) { s.Expected = "0644" }, func(s *CheckSpec) { s.Operator = "contains" }, func(s *CheckSpec) { s.TimeoutMs = 0 }} {
			bad := s
			change(&bad)
			if _, err := ParseCheck(programFilesJSON(bad)); err == nil {
				t.Fatal("weak definition accepted")
			}
		}
		var doc map[string]any
		json.Unmarshal([]byte(programFilesJSON(s)), &doc)
		for _, field := range []string{"cmd", "regex", "owner", "roots", "reference_path", "connection"} {
			doc[field] = nil
			raw, _ := json.Marshal(doc)
			if _, err := ParseCheck(string(raw)); err == nil {
				t.Fatal(field)
			}
			delete(doc, field)
		}
		doc["timeout_ms"] = nil
		raw, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatal("null timeout")
		}
		if runtime.GOOS == "windows" {
			if r := checkProgramFiles(&s); !r.Error || r.Passed {
				t.Fatal(r)
			}
		}
	}
}
func TestPrivilegedReferenceContractAndExactComparison(t *testing.T) {
	hash := strings.Repeat("a", 64)
	row := "amd64\t/usr/bin/fixture\t4755\t0\t0\t" + hash + "\n"
	valid := privilegedReferenceHeader + row + "arm64\t/usr/sbin/fixture\t2755\t0\t123\t" + hash + "\n"
	entries, err := parsePrivilegedReference(valid, "amd64")
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	arm, err := parsePrivilegedReference(valid, "arm64")
	if err != nil || len(arm) != 1 || arm[0].GID != 123 {
		t.Fatal(arm, err)
	}
	for _, bad := range []string{row, valid + row, strings.Replace(valid, "/usr/bin/fixture", "/usr/bin/../sbin/fixture", 1), strings.Replace(valid, "4755", "4777", 1), strings.Replace(valid, "4755", "0755", 1), strings.Replace(valid, "\t0\t0\t", "\t01\t0\t", 1), strings.Replace(valid, "\t0\t0\t", "\t0\t4294967296\t", 1), strings.Replace(valid, "amd64", "unknown", 1), strings.TrimSuffix(valid, "\n")} {
		if _, err := parsePrivilegedReference(bad, "amd64"); err == nil {
			t.Fatal("bad reference accepted", bad)
		}
	}
	if bad, sample := comparePrivilegedEntries(entries, entries); bad != 0 || sample != "" {
		t.Fatal(bad, sample)
	}
	for _, change := range []func(*privilegedEntry){func(e *privilegedEntry) { e.Mode = "2755" }, func(e *privilegedEntry) { e.GID = 1 }, func(e *privilegedEntry) { e.UID = 1 }, func(e *privilegedEntry) { e.SHA256 = strings.Repeat("b", 64) }} {
		copy := append([]privilegedEntry{}, entries...)
		change(&copy[0])
		if bad, _ := comparePrivilegedEntries(entries, copy); bad != 1 {
			t.Fatal(copy, bad)
		}
	}
	if bad, _ := comparePrivilegedEntries(entries, nil); bad != 1 {
		t.Fatal(bad)
	}
}
