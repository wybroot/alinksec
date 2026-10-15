package virusscan

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidSignaturePackagesPreserveUsablePreviousDatabase(t *testing.T) {
	work := t.TempDir()
	testDB(t, work, "trusted", strings.Repeat("a", 64))
	good := `{"db_version":"invalid","hash_count":1,"rule_count":0}`
	for _, test := range []struct {
		name    string
		entries [][2]string
	}{
		{"count", [][2]string{{"manifest.json", good}, {"hashes.txt", ""}}},
		{"duplicate", [][2]string{{"manifest.json", good}, {"manifest.json", good}, {"hashes.txt", ""}}},
		{"traversal", [][2]string{{"../outside", "unexpected"}}},
		{"invalid-rule", [][2]string{{"manifest.json", `{"db_version":"bad","hash_count":0,"rule_count":1}`}, {"hashes.txt", ""}, {"rules.json", `{"rules":[{"name":"bad","condition":"unsupported","strings":[{"value":"x"}]}]}`}}},
		{"expanded-limit", [][2]string{{"manifest.json", good}, {"hashes.txt", ""}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var b bytes.Buffer
			z := zip.NewWriter(&b)
			for _, e := range test.entries {
				f, err := z.Create(e[0])
				if err != nil {
					t.Fatal(err)
				}
				if test.name == "expanded-limit" && e[0] == "hashes.txt" {
					chunk := make([]byte, 64<<10)
					for i := 0; i < 1025; i++ {
						if _, err = f.Write(chunk); err != nil {
							t.Fatal(err)
						}
					}
				} else if _, err = f.Write([]byte(e[1])); err != nil {
					t.Fatal(err)
				}
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			pkg := filepath.Join(t.TempDir(), "candidate.zip")
			os.WriteFile(pkg, b.Bytes(), 0600)
			if err := InstallDB(work, pkg, ""); err == nil {
				t.Fatal("invalid package installed")
			}
			ReloadDB(work)
			db := LoadDB(work)
			if !db.Valid || db.Version != "trusted" || len(db.hashes) != 1 {
				t.Fatal("previous database damaged", db)
			}
		})
	}
}
func TestInvalidRulesDoNotSilentlyRemoveDetectionCoverage(t *testing.T) {
	for _, rule := range []string{
		`{"rules":[{"name":"bad","severity":0,"strings":[{"value":"x"}]}]}`,
		`{"rules":[{"name":"bad","platform":"unknown","strings":[{"value":"x"}]}]}`,
		`{"rules":[{"name":"bad","exts":["sh"],"strings":[{"value":"x"}]}]}`,
		`{"rules":[{"name":"bad","strings":[{"type":"regex","value":"x"}]}]}`,
		`{"rules":[{"name":"bad","strings":[{"type":"hex","value":"ZZ"}]}]}`,
	} {
		if _, err := compileRuleBytes([]byte(rule)); err == nil {
			t.Fatal("invalid rule accepted", rule)
		}
	}
	rules, err := compileRuleBytes([]byte(`{"rules":[{"name":"valid","condition":"all","exts":[".sh"],"strings":[{"value":"first"},{"type":"hex","value":"73 65 63 6f 6e 64"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if matchRules(rules, "test.sh", 12, []byte("first second")) == nil || matchRules(rules, "test.txt", 12, []byte("first second")) != nil || matchRules(rules, "test.sh", 5, []byte("first")) != nil {
		t.Fatal("internal rule conditions or extensions ignored")
	}
}
