package scap

import (
	"fmt"
	"strings"
	"testing"
)

func resultDocument() (*Content, string) {
	c := &Content{Manifest: Manifest{BenchmarkID: "xccdf_org.alinksec_benchmark_test", ProfileID: "xccdf_org.alinksec_profile_test"}}
	text := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.alinksec_benchmark_test"><TestResult id="xccdf_org.alinksec_testresult_test"><profile idref="xccdf_org.alinksec_profile_test"/>`
	for _, status := range []string{"pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed"} {
		id := "xccdf_org.alinksec_rule_" + status
		c.Rules = append(c.Rules, id)
		text += fmt.Sprintf(`<rule-result idref="%s" weight="1.0"><result>%s</result></rule-result>`, id, status)
	}
	return c, text + `<score system="urn:xccdf:scoring:default" maximum="100">50</score></TestResult></Benchmark>`
}
func TestStandardOutcomesStayDistinctAndEvidenceMustBeComplete(t *testing.T) {
	c, source := resultDocument()
	rules, scores, err := ParseResults([]byte(source), c)
	if err != nil || len(rules) != 9 || len(scores) != 1 {
		t.Fatalf("standard evidence: %v", err)
	}
	for _, r := range rules {
		if !strings.HasSuffix(r.RuleId, r.Result) {
			t.Fatal("outcome was coerced")
		}
	}
	for name, document := range map[string]string{
		"profile":        strings.Replace(source, "profile_test", "profile_other", 1),
		"benchmark":      strings.Replace(source, "benchmark_test", "benchmark_other", 1),
		"missing":        strings.Replace(source, `<rule-result idref="xccdf_org.alinksec_rule_pass" weight="1.0"><result>pass</result></rule-result>`, "", 1),
		"duplicate":      strings.Replace(source, "rule_fail", "rule_pass", 1),
		"unknown-status": strings.Replace(source, ">unknown<", ">successful<", 1),
		"invalid-weight": strings.Replace(source, `weight="1.0"`, `weight="NaN"`, 1),
		"invalid-score":  strings.Replace(source, ">50</score>", ">101</score>", 1),
		"entity":         `<!DOCTYPE Benchmark [<!ENTITY x SYSTEM "file:///etc/shadow">]>` + source,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseResults([]byte(document), c); err == nil {
				t.Fatal("unbound or incomplete evidence accepted")
			}
		})
	}
}
