package baseline

import (
	"crypto/sha256"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const linkerMetadataReference = "main+included_conf<=0644,dirs<=0755,uid=0,gid=0"
const privilegedReferencePath = "/etc/alinksec/privileged-files.reference"
const privilegedReferenceHeader = "alinksec-privileged-reference-v1\nscope=/usr/bin,/usr/sbin\n"

var privilegedReferenceExpected = regexp.MustCompile(`^scope=/usr/bin\+/usr/sbin,sha256=([a-f0-9]{64}),exact=mode/uid/gid/content$`)

func validProgramFiles(cs *CheckSpec) bool {
	return cs.Type == "linux_program_files" && cs.Target == "system-program-inputs" && cs.Operator == "eq" &&
		(cs.Option == "linker_metadata" && cs.Expected == linkerMetadataReference || cs.Option == "privileged_reference" && privilegedReferenceExpected.MatchString(cs.Expected))
}

type privilegedEntry struct {
	Path, Mode string
	UID, GID   uint32
	SHA256     string
}

func programInputName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 255 {
		return false
	}
	for _, c := range []byte(name) {
		if c < 33 || c > 126 || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}
func privilegedLogicalPath(value string) bool {
	parent := path.Dir(value)
	return (parent == "/usr/bin" || parent == "/usr/sbin") && path.Clean(value) == value && programInputName(path.Base(value))
}
func parsePrivilegedReference(raw string, arch string) ([]privilegedEntry, error) {
	if len(raw) > 64*1024 || !strings.HasPrefix(raw, privilegedReferenceHeader) || !strings.HasSuffix(raw, "\n") || arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("审核清单头部、范围、架构或大小未支持")
	}
	var selected []privilegedEntry
	counts := map[string]int{}
	seen := map[string]bool{}
	previous := ""
	for _, line := range strings.Split(strings.TrimPrefix(raw, privilegedReferenceHeader), "\n") {
		if line == "" {
			continue
		}
		if len(line) > 1024 {
			return nil, fmt.Errorf("审核清单物理行超限")
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 || (fields[0] != "amd64" && fields[0] != "arm64") || !privilegedLogicalPath(fields[1]) || !regexp.MustCompile(`^[0-7]{4}$`).MatchString(fields[2]) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(fields[5]) {
			return nil, fmt.Errorf("审核清单条目、路径或摘要格式未支持")
		}
		key := fields[0] + "\t" + fields[1]
		if seen[key] || previous != "" && key <= previous {
			return nil, fmt.Errorf("审核清单须按架构/路径排序且不能重复")
		}
		seen[key] = true
		previous = key
		counts[fields[0]]++
		if counts[fields[0]] > 128 {
			return nil, fmt.Errorf("每架构审核条目超过128")
		}
		mode, _ := strconv.ParseUint(fields[2], 8, 12)
		if mode&06000 == 0 || mode&0022 != 0 {
			return nil, fmt.Errorf("审核条目需SUID/SGID模式位且禁止组/其他写")
		}
		uid, e := strconv.ParseUint(fields[3], 10, 32)
		if e != nil || strconv.FormatUint(uid, 10) != fields[3] || uid != 0 {
			return nil, fmt.Errorf("审核条目需规范UID0")
		}
		gid, e := strconv.ParseUint(fields[4], 10, 32)
		if e != nil || strconv.FormatUint(gid, 10) != fields[4] {
			return nil, fmt.Errorf("审核条目GID非规范或越界")
		}
		if fields[0] == arch {
			selected = append(selected, privilegedEntry{fields[1], fields[2], uint32(uid), uint32(gid), fields[5]})
		}
	}
	return selected, nil
}
func privilegedEntriesDigest(entries []privilegedEntry) string {
	var body strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&body, "%s\t%s\t%d\t%d\t%s\n", e.Path, e.Mode, e.UID, e.GID, e.SHA256)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(body.String())))
}
func comparePrivilegedEntries(expected, actual []privilegedEntry) (int, string) {
	want, got := map[string]privilegedEntry{}, map[string]privilegedEntry{}
	for _, e := range expected {
		want[e.Path] = e
	}
	for _, e := range actual {
		got[e.Path] = e
	}
	var bad []string
	for path, e := range want {
		if got[path] != e {
			bad = append(bad, path)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			bad = append(bad, path)
		}
	}
	sort.Strings(bad)
	count := len(bad)
	// Full inventory and its digest are evaluated; evidence lists are bounded so
	// many long names cannot hide the outcome behind the report's 2048-byte cap.
	var sample []string
	budget := 0
	for _, name := range bad {
		if len(sample) >= 8 || budget+len(name) > 512 {
			break
		}
		sample = append(sample, strconv.Quote(name))
		budget += len(name)
	}
	return count, strings.Join(sample, ",")
}
func programFilesPrefix(option string) string {
	return "scope=ubuntu24-system-program-inputs option=" + option + " library_targets_state=unverified loader_cache_state=unverified preload_environment_state=unverified symlink_targets_state=unverified descendant_files_state=unverified other_paths_state=unverified effective_privilege_state=unverified authorization_process_state=unverified snapshot_state=non_atomic "
}
