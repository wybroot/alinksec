package virusscan

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxHashEntries = 250000
const maxExpandedBytes int64 = 64 << 20
const maxRuleBytes int64 = 2 << 20

var signatureVersion = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

func boundedFile(path string, limit int64) ([]byte, error) {
	f, parent, err := openRegular(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer parent.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("signature file too large")
	}
	return b, nil
}
func compileRuleBytes(data []byte) ([]*Rule, error) {
	if int64(len(data)) > maxRuleBytes {
		return nil, fmt.Errorf("rules too large")
	}
	var wrapper struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil || wrapper.Rules == nil || len(wrapper.Rules) > 2000 {
		return nil, fmt.Errorf("invalid rule document")
	}
	rules := make([]*Rule, 0, len(wrapper.Rules))
	names := map[string]bool{}
	for _, raw := range wrapper.Rules {
		var r Rule
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &r) != nil || json.Unmarshal(raw, &fields) != nil || strings.TrimSpace(r.Name) == "" || utf8.RuneCountInString(r.Name) > 255 || names[r.Name] || len(r.Strings) == 0 || len(r.Strings) > 64 {
			return nil, fmt.Errorf("invalid rule")
		}
		names[r.Name] = true
		if _, ok := fields["severity"]; !ok {
			r.Severity = 4
		}
		if r.Severity < 1 || r.Severity > 5 {
			return nil, fmt.Errorf("invalid rule severity")
		}
		if _, ok := fields["platform"]; !ok {
			r.Platform = "all"
		}
		if r.Platform != "all" && r.Platform != "linux" && r.Platform != "windows" {
			return nil, fmt.Errorf("invalid rule platform")
		}
		if _, ok := fields["condition"]; !ok {
			r.Condition = "all"
		}
		if r.Condition != "all" && r.Condition != "any" {
			return nil, fmt.Errorf("invalid rule condition")
		}
		if _, ok := fields["max_mb"]; !ok {
			r.MaxMB = 50
		}
		if r.MaxMB < 1 || r.MaxMB > 50 || len(r.Exts) > 64 {
			return nil, fmt.Errorf("invalid rule range")
		}
		for _, ext := range r.Exts {
			if len(ext) > 32 || !strings.HasPrefix(ext, ".") || strings.ContainsAny(ext, "/\\\x00") {
				return nil, fmt.Errorf("invalid rule extension")
			}
		}
		var patterns []map[string]json.RawMessage
		if json.Unmarshal(fields["strings"], &patterns) != nil {
			return nil, fmt.Errorf("invalid patterns")
		}
		for i := range r.Strings {
			pattern := &r.Strings[i]
			if _, ok := patterns[i]["type"]; !ok {
				pattern.Type = "text"
			}
			if pattern.Value == "" || utf8.RuneCountInString(pattern.Value) > 1024 {
				return nil, fmt.Errorf("invalid rule pattern")
			}
			switch pattern.Type {
			case "text":
				pattern.bytes = []byte(pattern.Value)
			case "hex":
				b, err := hex.DecodeString(strings.Join(strings.Fields(pattern.Value), ""))
				if err != nil || len(b) == 0 {
					return nil, fmt.Errorf("invalid hex pattern")
				}
				pattern.bytes = b
			default:
				return nil, fmt.Errorf("invalid rule pattern type")
			}
		}
		rules = append(rules, &r)
	}
	return rules, nil
}
func validateInstalledDB(dir string) error {
	db := parseDB(dir)
	if !db.Valid {
		return fmt.Errorf("invalid signature manifest, counts, hashes or rules")
	}
	return nil
}
func readRuleFile(dir string) ([]*Rule, error) {
	path := filepath.Join(dir, "rules.json")
	data, err := boundedFile(path, maxRuleBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return compileRuleBytes(data)
}
