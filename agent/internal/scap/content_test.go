package scap

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These minimal documents test the transport boundary only. Native standards
// validation is mandatory in the separate three-platform SCAP fixture job.
const boundaryXML = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" resolved="true" id="xccdf_org.alinksec_benchmark_test"><Profile id="xccdf_org.alinksec_profile_test"/><Rule id="xccdf_org.alinksec_rule_test"><title>Test</title></Rule></Benchmark>`

func archiveFor(t *testing.T, xmlText, manifest string, extra map[string]string) []byte {
	t.Helper()
	if manifest == "" {
		b, _ := json.Marshal(Manifest{SchemaVersion: 1, Code: "TEST", Version: "1", Name: "Transport boundary", OSType: 1, OSVersionPattern: ".*", BenchmarkFile: "test.xml", BenchmarkID: "xccdf_org.alinksec_benchmark_test", ProfileID: "xccdf_org.alinksec_profile_test"})
		manifest = string(b)
	}
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for name, data := range map[string]string{"alinksec-scap.json": manifest, "test.xml": xmlText} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range extra {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestOfflineContentBoundary(t *testing.T) {
	data := archiveFor(t, boundaryXML, "", nil)
	c, err := ParseContent(data)
	if err != nil || len(c.Rules) != 1 || c.SHA256 != Digest(data) {
		t.Fatalf("valid offline source: %v", err)
	}
	for name, xmlText := range map[string]string{
		"entity":         `<!DOCTYPE Benchmark [<!ENTITY x SYSTEM "file:///etc/shadow">]>` + boundaryXML,
		"unresolved":     strings.Replace(boundaryXML, `resolved="true"`, `resolved="false"`, 1),
		"inheritance":    strings.Replace(boundaryXML, `<Profile `, `<Profile extends="xccdf_org.alinksec_profile_other" `, 1),
		"repair":         strings.Replace(boundaryXML, "<title>Test</title>", `<title>Test</title><fix system="urn:xccdf:fix:script:sh">touch /tmp/should-never-run</fix>`, 1),
		"sce":            strings.Replace(boundaryXML, "<title>Test</title>", `<check system="http://open-scap.org/page/SCE"><check-content-ref href="check.sh"/></check>`, 1),
		"shell-probe":    strings.Replace(boundaryXML, "<title>Test</title>", `<shellcommand_test/>`, 1),
		"remote":         strings.Replace(boundaryXML, "<title>Test</title>", `<check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"><check-content-ref href="https://example.invalid/oval.xml"/></check>`, 1),
		"missing":        strings.Replace(boundaryXML, "<title>Test</title>", `<check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"><check-content-ref href="absent.xml"/></check>`, 1),
		"xinclude":       strings.Replace(boundaryXML, "<title>Test</title>", `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="test.xml"/>`, 1),
		"xml-base":       strings.Replace(boundaryXML, "<title>Test</title>", `<title xml:base="https://example.invalid/">Test</title>`, 1),
		"duplicate-rule": strings.Replace(boundaryXML, "</Benchmark>", `<Rule id="xccdf_org.alinksec_rule_test"/></Benchmark>`, 1),
		"wrong-profile":  strings.ReplaceAll(boundaryXML, "profile_test", "profile_other"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseContent(archiveFor(t, xmlText, "", nil)); err == nil {
				t.Fatal("unsafe or incomplete content accepted")
			}
		})
	}
	for _, name := range []string{"../outside.xml", "/absolute.xml", `C:\outside.xml`, "nested/../outside.xml", "script.sh"} {
		if _, err := ParseContent(archiveFor(t, boundaryXML, "", map[string]string{name: "x"})); err == nil {
			t.Fatalf("unsafe entry accepted: %s", name)
		}
	}
	manifest, _ := json.Marshal(c.Manifest)
	duplicate := strings.Replace(string(manifest), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)
	if _, err := ParseContent(archiveFor(t, boundaryXML, duplicate, nil)); err == nil {
		t.Fatal("duplicate manifest key accepted")
	}
}

func TestNativeScapEvidence(t *testing.T) {
	file := os.Getenv("ALINKSEC_SCAP_FIXTURE_ZIP")
	if file == "" {
		t.Skip("requires real native interpreter fixture")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	content, err := ParseContent(data)
	if err != nil {
		t.Fatalf("real SCAP content: %v", err)
	}
	found := 0
	err = filepath.WalkDir(os.Getenv("ALINKSEC_SCAP_RESULT_DIR"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.Contains(strings.ToUpper(entry.Name()), "XCCDF") || !strings.HasSuffix(strings.ToLower(path), ".xml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rules, scores, err := ParseResults(data, content)
		if err != nil {
			t.Fatalf("actual native XCCDF result: %v", err)
		}
		expected := map[string]string{"external": "pass", "failure": "fail", "compound": "pass", "unselected": "notselected", "platform": "notapplicable"}
		if len(rules) != len(expected) || len(scores) == 0 {
			t.Fatal("incomplete native evidence")
		}
		for _, rule := range rules {
			if expected[strings.TrimPrefix(rule.RuleId, "xccdf_org.alinksec_rule_")] != rule.Result {
				t.Fatalf("unexpected native outcome: %v", rule)
			}
		}
		found++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found != 1 {
		t.Fatalf("expected one fresh native result, got %d", found)
	}
}
