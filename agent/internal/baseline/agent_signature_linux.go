//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var signatureVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var signatureName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var signatureHash = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func strictDiskObject(raw []byte) (map[string]json.RawMessage, error) {
	failure := fmt.Errorf("strict object unavailable")
	if len(raw) > 16*1024 {
		return nil, failure
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, failure
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		name, ok := t.(string)
		if err != nil || !ok || fields[name] != nil {
			return nil, failure
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || string(value) == "null" {
			return nil, failure
		}
		fields[name] = value
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, failure
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, failure
	}
	return fields, nil
}

func parseSignatureDisk(manifest, hashes []byte) (SignatureObservation, error) {
	failure := fmt.Errorf("signature declarations unavailable")
	f, err := strictDiskObject(manifest)
	if err != nil || len(f) != 4 {
		return SignatureObservation{}, failure
	}
	var version, packageHash string
	var count, rules int
	if json.Unmarshal(f["db_version"], &version) != nil || !signatureVersion.MatchString(version) || json.Unmarshal(f["hash_count"], &count) != nil || count < 0 || count > 1024 || json.Unmarshal(f["rule_count"], &rules) != nil || rules != 0 || json.Unmarshal(f["sha256"], &packageHash) != nil || packageHash != "" && !signatureHash.MatchString(packageHash) {
		return SignatureObservation{}, failure
	}
	out := SignatureObservation{Version: version, HashCount: count, RuleCount: rules, Hashes: map[string]SignatureEntry{}}
	lines := strings.Split(strings.TrimSuffix(string(hashes), "\n"), "\n")
	if len(hashes) == 0 {
		lines = nil
	}
	if len(lines) > 1024 {
		return out, failure
	}
	for _, line := range lines {
		p := strings.Fields(line)
		if len(line) > 256 || len(p) != 3 || !signatureHash.MatchString(p[0]) || !signatureName.MatchString(p[1]) {
			return out, failure
		}
		sev, err := strconv.Atoi(p[2])
		hash := strings.ToLower(p[0])
		if err != nil || sev < 1 || sev > 5 {
			return out, failure
		}
		if _, ok := out.Hashes[hash]; ok {
			return out, failure
		}
		out.Hashes[hash] = SignatureEntry{Name: p[1], Severity: int32(sev)}
	}
	if len(out.Hashes) != count {
		return out, failure
	}
	return out, nil
}

func checkAgentSignature(cs *CheckSpec, rt *AgentRuntime) ItemResult {
	return agentSignatureWithin(cs, rt, 0, 0, true)
}
func agentSignatureWithin(cs *CheckSpec, rt *AgentRuntime, uid, gid uint32, parents bool) ItemResult {
	failure := func() ItemResult {
		return ItemResult{Error: true, Actual: agentSignaturePrefix, Message: "当前缓存、哈希清单、可信输入或读取稳定性无法确认"}
	}
	if rt == nil || rt.Signature == nil || !filepath.IsAbs(rt.WorkDir) || filepath.Clean(rt.WorkDir) != rt.WorkDir || rt.WorkDir == "/" {
		return failure()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	r := newPAMRead(cs.TimeoutMs)
	defer r.close()
	dirs := []string{rt.WorkDir, filepath.Join(rt.WorkDir, "virus"), filepath.Join(rt.WorkDir, "virus/db")}
	if parents {
		for parent := filepath.Dir(rt.WorkDir); ; parent = filepath.Dir(parent) {
			dirs = append([]string{parent}, dirs...)
			if parent == "/" {
				break
			}
		}
	}
	for _, dir := range dirs {
		if _, exists := r.inputs[dir]; exists {
			continue
		}
		if _, err := r.open(dir, true); err != nil || trustedDiskInput(r.inputs[dir], uid, gid) != nil {
			return failure()
		}
	}
	base := filepath.Join(rt.WorkDir, "virus/db")
	names, err := r.inputs[base].file.ReadDir(5)
	if err != nil && err != io.EOF || len(names) > 3 {
		return failure()
	}
	for _, name := range names {
		if name.Name() != "manifest.json" && name.Name() != "hashes.txt" && name.Name() != "rules.json" {
			return failure()
		}
	}
	manifest, err := boundedDiskInput(r, filepath.Join(base, "manifest.json"))
	if err != nil {
		return failure()
	}
	hashes, err := boundedDiskInput(r, filepath.Join(base, "hashes.txt"))
	if err != nil {
		return failure()
	}
	if info, err := os.Lstat(filepath.Join(base, "rules.json")); err == nil {
		if !info.Mode().IsRegular() {
			return failure()
		}
		raw, err := boundedDiskInput(r, filepath.Join(base, "rules.json"))
		f, e := strictDiskObject(raw)
		var rules []json.RawMessage
		if err != nil || e != nil || len(f) != 1 || json.Unmarshal(f["rules"], &rules) != nil || rules == nil || len(rules) != 0 {
			return failure()
		}
	} else if os.IsNotExist(err) {
		r.absent = append(r.absent, filepath.Join(base, "rules.json"))
	} else {
		return failure()
	}
	disk, err := parseSignatureDisk(manifest, hashes)
	if err != nil {
		return failure()
	}
	a, err := rt.Signature(ctx)
	if err != nil || a.Generation == 0 || a.Hashes == nil || len(a.Hashes) > 1024 || a.RuleCount != 0 {
		return failure()
	}
	b, err := rt.Signature(ctx)
	if err != nil || !reflect.DeepEqual(a, b) || ctx.Err() != nil {
		return failure()
	}
	for _, input := range r.inputs {
		if trustedDiskInput(input, uid, gid) != nil {
			return failure()
		}
	}
	if r.stable() != nil || ctx.Err() != nil {
		return failure()
	}
	match := a.Version == disk.Version && a.HashCount == disk.HashCount && reflect.DeepEqual(a.Hashes, disk.Hashes)
	keys := make([]string, 0, len(disk.Hashes))
	for key := range disk.Hashes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	canonical := strings.Builder{}
	for _, key := range keys {
		entry := disk.Hashes[key]
		fmt.Fprintf(&canonical, "%s %s %d\n", key, entry.Name, entry.Severity)
	}
	passed := disk.HashCount > 0 && match
	result := ItemResult{Passed: passed, Actual: fmt.Sprintf("%shash_count=%d rule_count=0 cache_reference_match=%t version_sha256=%x inventory_sha256=%x hashes_file_sha256=%x", agentSignaturePrefix, disk.HashCount, match, sha256.Sum256([]byte(disk.Version)), sha256.Sum256([]byte(canonical.String())), sha256.Sum256(hashes))}
	if !passed {
		result.Message = "非空哈希清单或当前缓存与磁盘一致性不满足参考"
	}
	return result
}
