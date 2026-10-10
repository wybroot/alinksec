//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var shadowDefaultsVersion = regexp.MustCompile(`^1:4\.13\+dfsg1-4ubuntu3(\.[0-9]+)?$`)
var shadowDefaultsDecimal = regexp.MustCompile(`^(?:-1|0|[1-9][0-9]*)$`)

type shadowDefaultsQuery func(context.Context, int) ItemResult

func queryShadowDefaultsVersion(ctx context.Context, timeout int) ItemResult {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${Version}", "passwd")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	return collectBaselineCommand(ctx, cmd, timeout)
}

func checkShadowAccountDefaults(cs *CheckSpec) ItemResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	return shadowDefaultsWithin(ctx, cs, shadowDefaultsTarget, 0, 0, queryShadowDefaultsVersion)
}

// Only selected disk declarations are observed. Production never invokes
// useradd, reads shadow credentials, changes accounts or tests authentication.
func shadowDefaultsWithin(ctx context.Context, cs *CheckSpec, target string, uid, gid uint32, query shadowDefaultsQuery) ItemResult {
	prefix := "scope=shadow-new-account-default-declarations target=/etc/login.defs option=" + cs.Option +
		" creation_invocation_state=unverified existing_account_state=unverified expiry_enforcement_state=unverified warning_delivery_state=unverified snapshot_state=non_atomic "
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: message} }
	if !validShadowDefaults(cs) {
		return failure("Shadow新账户默认声明定义无效")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return failure("Shadow新账户默认声明当前仅验证Ubuntu24 amd64/arm64")
	}
	first := query(ctx, cs.TimeoutMs)
	if first.Error || !shadowDefaultsVersion.MatchString(first.Actual) {
		return failure("需可查询的Ubuntu24 passwd 1:4.13+dfsg1-4ubuntu3系列")
	}
	prefix += "package_version=" + first.Actual + " "
	r := newPAMRead(cs.TimeoutMs)
	if deadline, ok := ctx.Deadline(); ok {
		r.deadline = deadline
	}
	defer r.close()
	parent := filepath.Dir(target)
	for _, dir := range []string{filepath.Dir(parent), parent} {
		if _, exists := r.inputs[dir]; exists {
			continue
		}
		if _, err := r.open(dir, true); err != nil {
			return failure("login.defs父目录不可读取或超限")
		}
		if err := trustedDiskInput(r.inputs[dir], uid, gid); err != nil {
			return failure("login.defs父目录属主、写权限或ACL不可信")
		}
	}
	lines, err := r.lines(target)
	if err != nil {
		return failure("login.defs必须为可读取的有界非链接普通文件")
	}
	if err := trustedDiskInput(r.inputs[target], uid, gid); err != nil {
		return failure("login.defs属主、写权限、硬链接或ACL不可信")
	}
	values, err := shadowDefaultDeclarations(lines)
	if err != nil {
		return failure("login.defs选中声明需唯一、规范十进制且在-1至2147483647范围；重复、引号、转义或额外字段未支持")
	}
	second := query(ctx, cs.TimeoutMs)
	if second.Error || second.Actual != first.Actual || ctx.Err() != nil {
		return failure("Shadow包查询变化、失败或超过共同截止时间")
	}
	if err := r.stable(); err != nil {
		return failure("login.defs输入在检查期间变化或超限")
	}
	for _, input := range r.inputs {
		if err := trustedDiskInput(input, uid, gid); err != nil {
			return failure("login.defs输入权限或ACL无法复核")
		}
	}
	text := func(key string) string {
		if value, ok := values[key]; ok {
			return strconv.FormatInt(value, 10)
		}
		return "absent"
	}
	max, hasMax := values["PASS_MAX_DAYS"]
	min, hasMin := values["PASS_MIN_DAYS"]
	warn, hasWarn := values["PASS_WARN_AGE"]
	passed := hasMax && max >= 1 && max <= 90 && (!hasMin || min <= max)
	if cs.Option == "warn_days" {
		passed = hasWarn && warn >= 7 && warn <= 14 && hasMax && max >= 1 && warn <= max
	}
	result := ItemResult{Passed: passed, Actual: prefix + fmt.Sprintf("max_days=%s min_days=%s warn_days=%s inputs=%d access_acl=none default_acl=none", text("PASS_MAX_DAYS"), text("PASS_MIN_DAYS"), text("PASS_WARN_AGE"), len(r.inputs))}
	if !passed {
		result.Message = "普通本地新账户的口令有效期或预警默认声明未满足项目参考；已有账户及实际创建调用未验证"
	}
	return result
}

func shadowDefaultDeclarations(lines []string) (map[string]int64, error) {
	values := map[string]int64{}
	for _, raw := range lines {
		// getdef.c uses a finite fgets buffer and only space/tab between fields.
		// Keep every physical line below that buffer, including ignored lines;
		// Unicode whitespace must never become a separator under LC_ALL=C.
		if len(raw) > 1000 {
			return nil, fmt.Errorf("physical line exceeds finite parser scope")
		}
		fields := strings.FieldsFunc(raw, func(c rune) bool { return c == ' ' || c == '\t' })
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		key := strings.ToUpper(fields[0])
		if key != "PASS_MAX_DAYS" && key != "PASS_MIN_DAYS" && key != "PASS_WARN_AGE" {
			continue // Other settings and consumers remain outside this scope.
		}
		_, duplicate := values[key]
		if key != fields[0] || duplicate || len(fields) != 2 || !shadowDefaultsDecimal.MatchString(fields[1]) {
			return nil, fmt.Errorf("unsupported selected declaration")
		}
		value, err := strconv.ParseInt(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("selected declaration out of range")
		}
		values[key] = value
	}
	return values, nil
}
