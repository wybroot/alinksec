//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var dnfVersion = regexp.MustCompile(`^4\.14\.[0-9]+$`)
var dnfSection = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
var dnfKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var dnfRepoFile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.repo$`)
var dnfRepoDirs = []string{"/etc/yum.repos.d", "/etc/yum/repos.d", "/etc/distro.repos.d"}

func parseDNFDeclarations(raw []byte) (map[string]map[string]string, error) {
	failure := fmt.Errorf("DNF declaration grammar unconfirmed")
	out := map[string]map[string]string{}
	section := ""
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 1025 {
		return nil, failure
	}
	for _, physical := range lines {
		if len(physical) > 4096 || strings.ContainsFunc(physical, func(c rune) bool { return c > 126 || c < 32 && c != '\t' && c != '\r' }) {
			return nil, failure
		}
		line := strings.TrimSpace(physical)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if !dnfSection.MatchString(section) || out[section] != nil || len(out) >= 64 {
				return nil, failure
			}
			out[section] = map[string]string{}
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || section == "" {
			return nil, failure
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if !dnfKey.MatchString(key) || key == "include" {
			return nil, failure
		}
		if _, exists := out[section][key]; exists {
			return nil, failure
		}
		out[section][key] = value
	}
	return out, nil
}

func dnfBool(values map[string]string, key string, inherited bool) (bool, error) {
	value, exists := values[key]
	if !exists {
		return inherited, nil
	}
	switch strings.ToLower(value) {
	case "1", "yes", "true", "on":
		return true, nil
	case "0", "no", "false", "off":
		return false, nil
	default:
		return false, fmt.Errorf("DNF boolean declaration unconfirmed")
	}
}

func checkDNFSignature(cs *CheckSpec) ItemResult {
	query := func(ctx context.Context) (string, error) {
		return collectBaselineCommand(ctx, cs.TimeoutMs, "/usr/bin/rpm", []string{"--query", "dnf", "--queryformat", "%{VERSION}"}, []string{"PATH=/usr/bin:/bin", "LC_ALL=C"})
	}
	return dnfSignatureWithin(cs, "/", query, 0, 0)
}

func dnfSignatureWithin(cs *CheckSpec, root string, version func(context.Context) (string, error), uid, gid uint32) ItemResult {
	failure := func() ItemResult {
		return ItemResult{Error: true, Actual: dnfSignaturePrefix, Message: "DNF版本、配置范围、可信输入或读取稳定性无法确认"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	a, err := version(ctx)
	if err != nil || !dnfVersion.MatchString(a) {
		return failure()
	}
	r := newPAMRead(cs.TimeoutMs)
	r.deadline, _ = ctx.Deadline()
	defer r.close()
	openDir := func(path string) error {
		if _, exists := r.inputs[path]; exists {
			return nil
		}
		if _, err := r.open(path, true); err != nil {
			return err
		}
		return trustedDiskInput(r.inputs[path], uid, gid)
	}
	etc := filepath.Join(root, "etc")
	for _, dir := range []string{etc, filepath.Join(etc, "dnf")} {
		if openDir(dir) != nil {
			return failure()
		}
	}
	mainRaw, err := boundedDiskInput(r, filepath.Join(etc, "dnf/dnf.conf"))
	if err != nil {
		return failure()
	}
	sections, err := parseDNFDeclarations(mainRaw)
	if err != nil || sections["main"] == nil {
		return failure()
	}
	main := sections["main"]
	if value, exists := main["reposdir"]; exists {
		dirs := strings.Fields(strings.ReplaceAll(value, ",", " "))
		if len(dirs) != len(dnfRepoDirs) {
			return failure()
		}
		for i, path := range dirs {
			if path != dnfRepoDirs[i] {
				return failure()
			}
		}
	}
	gpg, err := dnfBool(main, "gpgcheck", false)
	if err != nil {
		return failure()
	}
	metadata, err := dnfBool(main, "repo_gpgcheck", false)
	if err != nil {
		return failure()
	}
	local, err := dnfBool(main, "localpkg_gpgcheck", false)
	if err != nil {
		return failure()
	}
	repos := map[string]map[string]string{}
	for id, values := range sections {
		if id != "main" {
			repos[id] = values
		}
	}
	files := 0
	for _, original := range dnfRepoDirs {
		dir := filepath.Join(root, strings.TrimPrefix(original, "/"))
		parent := filepath.Dir(dir)
		if parent != etc {
			if _, err := os.Lstat(parent); os.IsNotExist(err) {
				r.absent = append(r.absent, parent, dir)
				continue
			} else if err != nil || openDir(parent) != nil {
				return failure()
			}
		}
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			r.absent = append(r.absent, dir)
			continue
		} else if err != nil || openDir(dir) != nil {
			return failure()
		}
		entries, err := r.inputs[dir].file.ReadDir(129)
		if err != nil && err != io.EOF || len(entries) > 128 {
			return failure()
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".repo") {
				continue
			}
			files++
			if files > 32 || !dnfRepoFile.MatchString(entry.Name()) {
				return failure()
			}
			raw, err := boundedDiskInput(r, filepath.Join(dir, entry.Name()))
			if err != nil {
				return failure()
			}
			parsed, err := parseDNFDeclarations(raw)
			if err != nil {
				return failure()
			}
			for id, values := range parsed {
				if id == "main" || repos[id] != nil || len(repos) >= 64 {
					return failure()
				}
				repos[id] = values
			}
		}
	}
	bad := 0
	keys := make([]string, 0, len(repos))
	for id := range repos {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	canonical := strings.Builder{}
	for _, id := range keys {
		values := repos[id]
		a, err := dnfBool(values, "gpgcheck", gpg)
		if err != nil {
			return failure()
		}
		b, err := dnfBool(values, "repo_gpgcheck", metadata)
		if err != nil {
			return failure()
		}
		// Disabled repositories are also covered: later enabling one must not
		// silently weaken the declaration reference.
		if _, err := dnfBool(values, "enabled", true); err != nil {
			return failure()
		}
		if !a || !b {
			bad++
		}
		fmt.Fprintf(&canonical, "%s gpgcheck=%t repo_gpgcheck=%t\n", id, a, b)
	}
	for _, input := range r.inputs {
		if trustedDiskInput(input, uid, gid) != nil {
			return failure()
		}
	}
	b, err := version(ctx)
	if err != nil || a != b || r.stable() != nil || ctx.Err() != nil {
		return failure()
	}
	passed := gpg && metadata && local && len(repos) > 0 && bad == 0
	result := ItemResult{Passed: passed, Actual: fmt.Sprintf("%sdnf_version=%s main_gpgcheck=%t main_repo_gpgcheck=%t localpkg_gpgcheck=%t repo_count=%d mismatched_repos=%d inventory_sha256=%x", dnfSignaturePrefix, a, gpg, metadata, local, len(repos), bad, sha256.Sum256([]byte(canonical.String())))}
	if !passed {
		result.Message = "DNF主配置或全部仓库的非空签名声明参考不满足"
	}
	return result
}
