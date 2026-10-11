//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signatureFixture(t *testing.T) (*CheckSpec, *AgentRuntime) {
	dir := t.TempDir()
	base := filepath.Join(dir, "virus/db")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"db_version":"private_version","hash_count":1,"rule_count":0,"sha256":""}`
	pamWrite(t, filepath.Join(base, "manifest.json"), manifest)
	pamWrite(t, filepath.Join(base, "hashes.txt"), strings.Repeat("a", 64)+" PRIVATE_SIGNATURE 3\n")
	cs, _ := ParseCheck(agentRuntimeDefinition("hash_inventory"))
	rt := &AgentRuntime{WorkDir: dir, Signature: func(context.Context) (SignatureObservation, error) {
		return SignatureObservation{Generation: 1, Version: "private_version", HashCount: 1, Hashes: map[string]SignatureEntry{strings.Repeat("a", 64): {Name: "PRIVATE_SIGNATURE", Severity: 3}}}, nil
	}}
	return cs, rt
}

func TestAgentSignatureCacheDiskStatesAndPrivacy(t *testing.T) {
	for _, kind := range []string{"match", "cache_stale", "cache_empty", "empty_disk", "rule_scope", "count_mismatch", "duplicate", "manifest_duplicate", "unknown_manifest", "bad_severity", "extra_file", "missing", "writable", "symlink", "cache_generation", "replacement", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			cs, rt := signatureFixture(t)
			base := filepath.Join(rt.WorkDir, "virus/db")
			pass, executionError := kind == "match", true
			if kind == "match" || kind == "cache_stale" || kind == "cache_empty" || kind == "empty_disk" {
				executionError = false
			}
			original := rt.Signature
			switch kind {
			case "cache_stale":
				rt.Signature = func(ctx context.Context) (SignatureObservation, error) {
					v, e := original(ctx)
					v.Version = "old"
					return v, e
				}
			case "cache_empty":
				rt.Signature = func(context.Context) (SignatureObservation, error) {
					return SignatureObservation{Generation: 1, Hashes: map[string]SignatureEntry{}}, nil
				}
			case "empty_disk":
				pamWrite(t, filepath.Join(base, "manifest.json"), `{"db_version":"private_version","hash_count":0,"rule_count":0,"sha256":""}`)
				pamWrite(t, filepath.Join(base, "hashes.txt"), "")
			case "rule_scope":
				pamWrite(t, filepath.Join(base, "manifest.json"), `{"db_version":"private_version","hash_count":1,"rule_count":1,"sha256":""}`)
			case "count_mismatch":
				pamWrite(t, filepath.Join(base, "hashes.txt"), "")
			case "duplicate":
				pamWrite(t, filepath.Join(base, "hashes.txt"), strings.Repeat("a", 64)+" PRIVATE_SIGNATURE 3\n"+strings.Repeat("a", 64)+" PRIVATE_SIGNATURE 3\n")
			case "manifest_duplicate":
				pamWrite(t, filepath.Join(base, "manifest.json"), `{"db_version":"private_version","db_version":"other","hash_count":1,"rule_count":0,"sha256":""}`)
			case "unknown_manifest":
				pamWrite(t, filepath.Join(base, "manifest.json"), `{"db_version":"private_version","hash_count":1,"rule_count":0,"extra":0}`)
			case "bad_severity":
				pamWrite(t, filepath.Join(base, "hashes.txt"), strings.Repeat("a", 64)+" PRIVATE_SIGNATURE 7\n")
			case "extra_file":
				pamWrite(t, filepath.Join(base, "hidden.txt"), "PRIVATE_SIGNATURE")
			case "missing":
				os.Remove(filepath.Join(base, "hashes.txt"))
			case "writable":
				os.Chmod(filepath.Join(base, "hashes.txt"), 0666)
			case "symlink":
				os.Remove(filepath.Join(base, "hashes.txt"))
				os.Symlink(filepath.Join(base, "manifest.json"), filepath.Join(base, "hashes.txt"))
			case "cache_generation":
				calls := 0
				rt.Signature = func(ctx context.Context) (SignatureObservation, error) {
					calls++
					v, e := original(ctx)
					v.Generation = uint64(calls)
					return v, e
				}
			case "replacement":
				rt.Signature = func(ctx context.Context) (SignatureObservation, error) {
					pamWrite(t, filepath.Join(base, "replacement"), "changed\n")
					os.Rename(filepath.Join(base, "replacement"), filepath.Join(base, "hashes.txt"))
					return original(ctx)
				}
			case "cancel":
				rt.Signature = func(ctx context.Context) (SignatureObservation, error) {
					<-ctx.Done()
					return SignatureObservation{}, ctx.Err()
				}
			}
			r := agentSignatureWithin(cs, rt, uint32(os.Geteuid()), uint32(os.Getegid()), false)
			if r.Passed != pass || r.Error != executionError || strings.Contains(r.Actual+r.Message, "PRIVATE_SIGNATURE") || strings.Contains(r.Actual+r.Message, "private_version") {
				t.Fatal(r)
			}
		})
	}
}

func TestAgentSignatureStrictMetadataAndLimits(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{} {}`, `{"db_version":null,"hash_count":1,"rule_count":0,"sha256":""}`, `{"db_version":"v1","hash_count":1.0,"rule_count":0,"sha256":""}`, `{"db_version":"v1","hash_count":1025,"rule_count":0,"sha256":""}`} {
		if _, err := parseSignatureDisk([]byte(raw), nil); err == nil {
			t.Fatal("accepted ambiguous metadata")
		}
	}
	cs, rt := signatureFixture(t)
	pamWrite(t, filepath.Join(rt.WorkDir, "virus/db/rules.json"), `{"rules":[]}`)
	if r := agentSignatureWithin(cs, rt, uint32(os.Geteuid()), uint32(os.Getegid()), false); r.Error || !r.Passed {
		t.Fatal(r)
	}
	for _, raw := range []string{`{"rules":null}`, `{"rules":[],"rules":[]}`, `{"rules":[{}]}`} {
		pamWrite(t, filepath.Join(rt.WorkDir, "virus/db/rules.json"), raw)
		if r := agentSignatureWithin(cs, rt, uint32(os.Geteuid()), uint32(os.Getegid()), false); !r.Error {
			t.Fatal(r)
		}
	}
	var fields map[string]any
	json.Unmarshal([]byte(`{"db_version":"v1","hash_count":1,"rule_count":0,"sha256":""}`), &fields)
	fields["db_version"] = strings.Repeat("x", 65)
	raw, _ := json.Marshal(fields)
	if _, err := parseSignatureDisk(raw, []byte(strings.Repeat("a", 64)+" NAME 3\n")); err == nil {
		t.Fatal("unbounded version")
	}
}
