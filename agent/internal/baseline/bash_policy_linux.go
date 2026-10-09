//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

type bashVendorPrefix struct {
	bytes  int
	sha256 string
}
type bashPolicyPaths struct {
	etc             string
	profile, bashrc bashVendorPrefix
	uid, gid        uint32
}

var bashInstalledVersions = regexp.MustCompile(`^ii \tbase-files\t13ubuntu10(?:\.[0-9]+)?\nii \tbash\t5\.2\.21-2ubuntu4(?:\.[0-9]+)?$`)
var bashFragmentName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,120}\.sh$`)

func systemBashPolicyPaths() bashPolicyPaths {
	return bashPolicyPaths{etc: "/etc", profile: bashVendorPrefix{582, "66f4510566d71c4a49717f54a29d8c4268fd332a49595dbe78c072e06e5ca60f"}, bashrc: bashVendorPrefix{2319, "29128d49b590338131373ec431a59c0b5318330050aac9ac61d5098517ac9a25"}}
}
func queryBashPolicyVersions(ctx context.Context, timeout int) ItemResult {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "--show", "--showformat=${db:Status-Abbrev}\t${Package}\t${Version}\n", "--", "base-files", "bash")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	return collectBaselineCommand(ctx, cmd, timeout)
}
func checkBashGlobalPolicy(cs *CheckSpec) ItemResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cs.TimeoutMs)*time.Millisecond)
	defer cancel()
	return bashPolicyWithin(ctx, cs, systemBashPolicyPaths(), queryBashPolicyVersions)
}
func bashPolicyWithin(ctx context.Context, cs *CheckSpec, paths bashPolicyPaths, query func(context.Context, int) ItemResult) ItemResult {
	mode := "login_interactive"
	if cs.Option == "nonlogin_umask" {
		mode = "nonlogin_interactive"
	}
	prefix := "scope=ubuntu24-bash-global-startup-declarations context=" + mode + " option=" + cs.Option + " startup_environment_state=unverified personal_startup_state=unverified invocation_state=unverified existing_shell_state=unverified timeout_enforcement_state=unverified history_delivery_state=unverified snapshot_state=non_atomic "
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: message} }
	if !validBashPolicy(cs) || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return failure("Bash全局声明仅支持Ubuntu24 amd64/arm64固定范围与完整参考")
	}
	first := query(ctx, cs.TimeoutMs)
	if first.Error || !bashInstalledVersions.MatchString(first.Actual) {
		return failure("需完整安装Ubuntu24 bash5.2.21/base-files13ubuntu10系列")
	}
	versions := strings.Split(first.Actual, "\n")
	prefix += "base_files_version=" + strings.TrimPrefix(versions[0], "ii \tbase-files\t") + " bash_version=" + strings.TrimPrefix(versions[1], "ii \tbash\t") + " "
	r := newPAMRead(cs.TimeoutMs)
	if deadline, ok := ctx.Deadline(); ok {
		r.deadline = deadline
	}
	defer r.close()
	trusted := func(path string) error {
		input := r.inputs[path]
		if err := trustedDiskInput(input, paths.uid, paths.gid); err != nil {
			return err
		}
		if input.info.IsDir() && input.info.Mode().Perm()&0001 == 0 || !input.info.IsDir() && input.info.Mode().Perm()&0004 == 0 {
			return fmt.Errorf("global declarations require ordinary-user traversal/readability")
		}
		return nil
	}
	for _, dir := range []string{filepath.Dir(paths.etc), paths.etc} {
		if _, err := r.open(dir, true); err != nil {
			return failure("Bash配置父目录缺失、超限或不可信")
		}
		if err := trusted(dir); err != nil {
			return failure("Bash配置父目录UID/GID、写权限、ACL或遍历权限不可信")
		}
	}
	read := func(path string) (string, error) {
		f, err := r.open(path, false)
		if err != nil {
			return "", err
		}
		if err := trusted(path); err != nil {
			return "", err
		}
		raw, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
		r.bytes += len(raw)
		if err != nil || len(raw) > 64*1024 || r.bytes > 256*1024 || r.budget() != nil || ctx.Err() != nil || !utf8.Valid(raw) || strings.Count(string(raw), "\n") > 1024 || len(raw) > 0 && raw[len(raw)-1] != '\n' {
			return "", fmt.Errorf("read failure or64KiB/256KiB/1024lines/deadline exceeded")
		}
		for _, c := range raw {
			if c < 32 && c != '\n' && c != '\t' || c == 127 {
				return "", fmt.Errorf("unsupported control character")
			}
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if len(line) > 1024 {
				return "", fmt.Errorf("physical line exceeds1024bytes")
			}
		}
		return string(raw), nil
	}
	trailer := func(path string, vendor bashVendorPrefix) (string, error) {
		body, err := read(path)
		if err != nil {
			return "", err
		}
		if len(body) < vendor.bytes || fmt.Sprintf("%x", sha256.Sum256([]byte(body[:vendor.bytes]))) != vendor.sha256 {
			return "", fmt.Errorf("unconfirmed Ubuntu24 stock startup prefix")
		}
		return body[vendor.bytes:], nil
	}
	d := newBashDeclarations()
	var profileTrailer string
	if mode == "login_interactive" {
		var err error
		profileTrailer, err = trailer(filepath.Join(paths.etc, "profile"), paths.profile)
		if err != nil {
			return failure("Bash登录启动入口不可确认或超限")
		}
	}
	base, err := trailer(filepath.Join(paths.etc, "bash.bashrc"), paths.bashrc)
	if err != nil {
		return failure("Bash系统bashrc原始入口、权限或读取不可确认")
	}
	if err := d.parse(base); err != nil {
		return failure("Bash系统bashrc尾部不是已支持字面声明或违反readonly")
	}
	var names []string
	parts := filepath.Join(paths.etc, "profile.d")
	if mode == "login_interactive" {
		f, err := r.open(parts, true)
		if err != nil {
			return failure("Bash登录片段目录必须存在且可信")
		}
		if err := trusted(parts); err != nil {
			return failure("Bash登录片段目录UID/GID、权限或ACL不可信")
		}
		names, err = aptNames(f)
		if err != nil {
			return failure("Bash登录片段目录超过128条目或名称未支持")
		}
		selected := 0
		for _, name := range names {
			if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".sh") {
				continue
			}
			if !bashFragmentName.MatchString(name) {
				return failure("Bash登录片段名称未支持")
			}
			selected++
			if selected > 32 {
				return failure("Bash登录片段超过32个")
			}
			body, err := read(filepath.Join(parts, name))
			if err != nil {
				return failure("Bash登录片段不可读取、不可信或超限")
			}
			if err := d.parse(body); err != nil {
				return failure("Bash登录片段有未支持命令、替换、控制流或readonly覆盖")
			}
		}
		if err := d.parse(profileTrailer); err != nil {
			return failure("Bash登录profile尾部有未支持声明或readonly覆盖")
		}
	}
	second := query(ctx, cs.TimeoutMs)
	if second.Error || first.Actual != second.Actual || ctx.Err() != nil || r.stable() != nil {
		return failure("Bash包或配置输入变化、读取失败或共同截止时间耗尽")
	}
	if mode == "login_interactive" {
		again, err := aptNames(r.inputs[parts].file)
		if err != nil || strings.Join(names, "\x00") != strings.Join(again, "\x00") {
			return failure("Bash登录片段目录成员在检查期间变化")
		}
	}
	for path := range r.inputs {
		if err := trusted(path); err != nil {
			return failure("Bash配置权限或ACL无法复核")
		}
	}
	result := d.result(cs.Option)
	result.Actual = prefix + result.Actual + fmt.Sprintf(" inputs=%d bytes=%d access_acl=none default_acl=none", len(r.inputs), r.bytes)
	return result
}
