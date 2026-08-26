// Package fixer 配置类一键修复执行器（docs/05 §3.2）。
//
// 事务化执行：备份全部目标（文件副本+原属性）→ 按序执行 steps → 复核（重跑 check）
// → 失败全量回滚 → 上报 rolled_back。requires_restart 的服务重启默认不执行（仅标记）。
package fixer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Step fix_spec.steps 单步定义
type Step struct {
	Action   string `json:"action"`
	Path     string `json:"path"`
	Line     string `json:"line"`
	Position string `json:"position"` // append / replace_regex / after
	Pattern  string `json:"pattern"`  // replace_regex / after 的匹配正则
	Key      string `json:"key"`      // sysctl_set
	Value    string `json:"value"`    // sysctl_set
	Mode     string `json:"mode"`     // chmod
}

// execStep 执行单步，返回涉及文件（用于备份收集）
func execStep(s Step, log func(string, ...any)) error {
	switch s.Action {
	case "file_line_ensure":
		return fileLineEnsure(s.Path, s.Line, s.Position, s.Pattern)
	case "sysctl_set":
		return sysctlSet(s.Key, s.Value)
	case "chmod":
		return chmodPath(s.Path, s.Mode)
	case "file_replace":
		return fileReplace(s.Path, s.Pattern, s.Value)
	case "service_restart":
		// 客户可能不接受业务瞬断：默认仅提示，不执行重启（复核若依赖服务重载则不通过，人工介入）
		log("service_restart 默认不执行（requires_restart 人工窗口处理）", "service", s.Value)
		return nil
	case "chown", "registry_set", "audit_rule":
		return fmt.Errorf("动作 %s 暂不支持（当前版本）", s.Action)
	default:
		return fmt.Errorf("未知动作 %q", s.Action)
	}
}

// stepFiles 收集步骤涉及的需备份文件路径
func stepFiles(s Step) []string {
	switch s.Action {
	case "file_line_ensure", "file_replace", "chmod", "chown":
		if s.Path != "" {
			return []string{s.Path}
		}
	case "sysctl_set":
		// /proc/sys 即时值 + 持久化配置文件
		return []string{sysctlConfPath(), sysctlProcPath(s.Key)}
	}
	return nil
}

/* ==================== file_line_ensure ==================== */

// fileLineEnsure 行存在性保证：
//   - append：文件末尾追加（已存在完全相同行则跳过）
//   - replace_regex：首个匹配 pattern 的行替换为新行（无匹配则追加）
//   - after：插入到首个匹配 pattern 的行之后（无匹配则追加）
func fileLineEnsure(path, line, position, pattern string) error {
	if path == "" || line == "" {
		return fmt.Errorf("file_line_ensure 需要 path 与 line")
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("读取 %s: %w", path, err)
	}
	content := string(data)
	lines := splitLines(content)

	// 幂等：已存在完全相同行则直接成功
	for _, l := range lines {
		if strings.TrimSpace(l) == strings.TrimSpace(line) {
			return nil
		}
	}

	var re *regexp.Regexp
	if position == "replace_regex" || position == "after" {
		if pattern == "" {
			return fmt.Errorf("position=%s 需要 pattern", position)
		}
		if re, err = regexp.Compile(pattern); err != nil {
			return fmt.Errorf("pattern 编译失败: %w", err)
		}
	}

	switch position {
	case "", "append":
		lines = append(lines, line)
	case "replace_regex":
		replaced := false
		for i, l := range lines {
			if !replaced && re.MatchString(l) {
				lines[i] = line
				replaced = true
			}
		}
		if !replaced {
			lines = append(lines, line)
		}
	case "after":
		inserted := false
		var out []string
		for _, l := range lines {
			out = append(out, l)
			if !inserted && re.MatchString(l) {
				out = append(out, line)
				inserted = true
			}
		}
		if !inserted {
			out = append(out, line)
		}
		lines = out
	default:
		return fmt.Errorf("不支持的 position %q", position)
	}

	newContent := strings.Join(lines, "\n") + "\n"
	return writeFileKeepMode(path, []byte(newContent))
}

/* ==================== file_replace ==================== */

// fileReplace regex 全文替换（value 为替换文本，$1 可用）
func fileReplace(path, pattern, value string) error {
	if path == "" || pattern == "" {
		return fmt.Errorf("file_replace 需要 path 与 pattern")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取 %s: %w", path, err)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("pattern 编译失败: %w", err)
	}
	return writeFileKeepMode(path, []byte(re.ReplaceAllString(string(data), value)))
}

/* ==================== sysctl_set ==================== */

func sysctlProcPath(key string) string {
	return filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
}

func sysctlConfPath() string {
	return "/etc/sysctl.d/99-alinksec.conf"
}

// sysctlSet 即时生效（写 /proc/sys）+ 持久化（99-alinksec.conf，行幂等）
func sysctlSet(key, value string) error {
	if key == "" {
		return fmt.Errorf("sysctl_set 需要 key")
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("sysctl_set 仅支持 Linux")
	}
	// 即时生效（失败不阻断：仅持久化也可行，复核用 cmd_output sysctl -n 会暴露）
	if err := os.WriteFile(sysctlProcPath(key), []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("写 /proc/sys: %w", err)
	}
	// 持久化：key = value 行幂等追加
	return fileLineEnsure(sysctlConfPath(), key+" = "+value, "replace_regex",
		`^\s*#?\s*`+regexp.QuoteMeta(key)+`\s*=`)
}

/* ==================== chmod ==================== */

func chmodPath(path, mode string) error {
	if path == "" || mode == "" {
		return fmt.Errorf("chmod 需要 path 与 mode")
	}
	var m uint32
	if _, err := fmt.Sscanf(mode, "%o", &m); err != nil {
		return fmt.Errorf("mode %q 解析失败: %w", mode, err)
	}
	if err := os.Chmod(path, os.FileMode(m)); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

/* ==================== 备份与回滚 ==================== */

// fileBackup 单文件备份：内容副本 + 原 mode；原不存在则标记（回滚时删除新建文件）
type fileBackup struct {
	path    string
	existed bool
	mode    os.FileMode
	content []byte
}

// backupFiles 备份一组文件（去重）；读失败的文件返回错误（宁可不修也不留无法回滚的现场）
func backupFiles(paths []string) (map[string]*fileBackup, error) {
	seen := map[string]bool{}
	backups := map[string]*fileBackup{}
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		st, err := os.Stat(p)
		if os.IsNotExist(err) {
			backups[p] = &fileBackup{path: p, existed: false}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("读取备份 %s: %w", p, err)
		}
		backups[p] = &fileBackup{path: p, existed: true, mode: st.Mode().Perm(), content: data}
	}
	return backups, nil
}

// rollback 全量回滚：恢复内容+权限；修复期间新建的文件删除
func rollback(backups map[string]*fileBackup) error {
	var firstErr error
	for _, b := range backups {
		if !b.existed {
			if err := os.Remove(b.path); err != nil && !os.IsNotExist(err) && firstErr == nil {
				firstErr = fmt.Errorf("删除新建文件 %s: %w", b.path, err)
			}
			continue
		}
		if err := writeFileKeepMode(b.path, b.content); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := os.Chmod(b.path, b.mode); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("恢复权限 %s: %w", b.path, err)
		}
	}
	return firstErr
}

/* ==================== 工具 ==================== */

// writeFileKeepMode 写文件：目录不存在则创建（父目录 0755）；已有文件保留原权限
func writeFileKeepMode(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建目录 %s: %w", dir, err)
		}
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(path, data, mode)
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// runServiceCtl 服务控制（预留：service_restart 打开开关后启用）
func runServiceCtl(service string) error {
	if runtime.GOOS == "windows" {
		return exec.Command("net", "stop", service).Run()
	}
	ctx := exec.Command("/bin/sh", "-c", "systemctl restart "+service+" 2>/dev/null || service "+service+" restart")
	return ctx.Run()
}

var _ = time.Second // 保留 time 引用（runServiceCtl 超时控制后续接入）
