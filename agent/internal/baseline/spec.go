// Package baseline 基线核查引擎：解释执行服务端下发的 check JSON（docs/04 §3.2）。
//
// 支持声明式文件、固定命令和产品配置检查：
//   - file_content：目标文件任意行匹配 regex
//   - file_line：   目标文件行级断言（regex / contains / not_contains）
//   - file_perm：   文件权限/属主断言（Linux）
//   - cmd_output：  命令执行输出断言（eq / ne / contains / not_contains / regex）
//   - sshd_effective：OpenSSH 对明确连接条件的配置解析（Linux）
package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// CheckSpec check JSON 反序列化结构（字段按检查类型取并集，未知字段拒绝）
type CheckSpec struct {
	Type       string         `json:"type"`
	Target     string         `json:"target"`
	Regex      string         `json:"regex"`
	Operator   string         `json:"operator"`
	Expected   string         `json:"expected"`
	Cmd        string         `json:"cmd"`
	Perm       string         `json:"perm"`
	Owner      string         `json:"owner"`
	Group      string         `json:"group"`
	TimeoutMs  int            `json:"timeout_ms"`
	Option     string         `json:"option,omitempty"`
	Connection *SSHConnection `json:"connection,omitempty"`
}

// SSHConnection is explicit so Match rules are evaluated for a known connection.
// Values are data passed as one -C argument, never shell text or extra flags.
type SSHConnection struct {
	User         string `json:"user"`
	Host         string `json:"host"`
	Address      string `json:"address"`
	LocalAddress string `json:"local_address"`
	LocalPort    int    `json:"local_port"`
}

func (c *SSHConnection) validate() error {
	if c == nil || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`).MatchString(c.User) ||
		!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`).MatchString(c.Host) || c.LocalPort < 1 || c.LocalPort > 65535 {
		return fmt.Errorf("SSH 检查需明确有效的用户、来源主机和本地端口")
	}
	for _, value := range []string{c.Address, c.LocalAddress} {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.Is6() && strings.Contains(value, ".") {
			return fmt.Errorf("SSH 连接地址必须为不带区域的 IPv4 或 IPv6 字面值")
		}
	}
	return nil
}

func (c *SSHConnection) argument() string {
	return fmt.Sprintf("user=%s,host=%s,addr=%s,laddr=%s,lport=%d", c.User, c.Host, c.Address, c.LocalAddress, c.LocalPort)
}

// ParseCheck 解析 check JSON；type 缺失或无法解析时返回错误（该项按失败落库）
func ParseCheck(checkJSON string) (*CheckSpec, error) {
	if len(checkJSON) > 16*1024 {
		return nil, fmt.Errorf("check JSON 超过 16 KiB 上限")
	}
	// Reject duplicate keys rather than silently executing the last definition.
	scan := json.NewDecoder(strings.NewReader(checkJSON))
	first, err := scan.Token()
	if err != nil || first != json.Delim('{') {
		return nil, fmt.Errorf("check JSON 必须为对象")
	}
	seen := map[string]bool{}
	for scan.More() {
		key, err := scan.Token()
		if err != nil {
			return nil, fmt.Errorf("check JSON 解析失败: %w", err)
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return nil, fmt.Errorf("check JSON 含重复字段")
		}
		seen[name] = true
		var value json.RawMessage
		if err := scan.Decode(&value); err != nil {
			return nil, fmt.Errorf("check JSON 解析失败: %w", err)
		}
		if name == "connection" {
			var connection map[string]json.RawMessage
			if err := json.Unmarshal(value, &connection); err != nil {
				return nil, fmt.Errorf("SSH connection 必须为对象")
			}
			d := json.NewDecoder(strings.NewReader(string(value)))
			if token, _ := d.Token(); token != json.Delim('{') {
				return nil, fmt.Errorf("SSH connection 必须为对象")
			}
			keys := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return nil, fmt.Errorf("SSH connection 含重复字段")
				}
				keys[name] = true
				if err := d.Decode(new(json.RawMessage)); err != nil {
					return nil, err
				}
			}
		}
	}
	if _, err := scan.Token(); err != nil {
		return nil, fmt.Errorf("check JSON 解析失败: %w", err)
	}
	var s CheckSpec
	decoder := json.NewDecoder(strings.NewReader(checkJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return nil, fmt.Errorf("check JSON 解析失败: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("check JSON 含尾随内容")
	}
	switch s.Type {
	case "file_content", "file_line", "file_perm", "cmd_output", "sshd_effective":
	default:
		return nil, fmt.Errorf("不支持的检查类型: %q", s.Type)
	}
	if s.TimeoutMs == 0 {
		s.TimeoutMs = 5000
	}
	if s.TimeoutMs < 100 || s.TimeoutMs > 30000 {
		return nil, fmt.Errorf("检查超时需为 100 至 30000 毫秒")
	}
	if utf8.RuneCountInString(s.Expected) > 1000 || utf8.RuneCountInString(s.Regex) > 1000 || utf8.RuneCountInString(s.Target) > 1024 || len(s.Cmd) > 2048 {
		return nil, fmt.Errorf("检查字段超过长度上限")
	}
	if strings.HasPrefix(s.Type, "file_") && !filepath.IsAbs(s.Target) {
		return nil, fmt.Errorf("文件检查必须使用绝对路径")
	}
	if s.Type == "sshd_effective" {
		if !filepath.IsAbs(s.Target) || strings.ContainsRune(s.Target, '\x00') || s.Cmd != "" || s.Regex != "" ||
			s.Perm != "" || s.Owner != "" || s.Group != "" ||
			(s.Option != "permitrootlogin" && s.Option != "maxauthtries") {
			return nil, fmt.Errorf("SSH 检查只支持绝对配置路径及已实现的配置项")
		}
		if err := s.Connection.validate(); err != nil {
			return nil, err
		}
		if s.Option == "permitrootlogin" && s.Connection.User != "root" {
			return nil, fmt.Errorf("root 登录策略必须使用 root 连接条件")
		}
		if s.Expected == "" {
			return nil, fmt.Errorf("SSH 检查需指定期望值")
		}
		switch s.Operator {
		case "eq", "regex":
		default:
			return nil, fmt.Errorf("SSH 检查仅支持 eq 或 regex")
		}
	} else if s.Option != "" || s.Connection != nil {
		return nil, fmt.Errorf("SSH 字段不能用于其他检查类型")
	}
	pattern := ""
	if s.Type == "file_content" {
		if s.Regex == "" {
			return nil, fmt.Errorf("file_content 必须指定非空 regex")
		}
		pattern = s.Regex
	}
	if s.Type == "file_line" {
		if s.Operator != "regex" && s.Operator != "contains" && s.Operator != "not_contains" || s.Expected == "" {
			return nil, fmt.Errorf("file_line 需要有效运算符和非空期望值")
		}
	}
	if s.Type == "file_perm" {
		if len(s.Perm) > 4 || utf8.RuneCountInString(s.Owner) > 64 || utf8.RuneCountInString(s.Group) > 64 {
			return nil, fmt.Errorf("文件权限或属主字段超过长度上限")
		}
		if s.Perm != "" && !regexp.MustCompile(`^[0-7]{4}$`).MatchString(s.Perm) {
			return nil, fmt.Errorf("文件权限必须为四位八进制")
		}
	}
	if s.Type == "cmd_output" {
		if s.Cmd == "" {
			return nil, fmt.Errorf("cmd_output 必须指定命令选择器")
		}
		switch s.Operator {
		case "", "eq", "ne", "contains", "not_contains", "regex", "gt", "gte", "lt", "lte":
		default:
			return nil, fmt.Errorf("不支持的命令比较运算符")
		}
	}
	if s.Operator == "regex" {
		pattern = s.Expected
	}
	if pattern != "" {
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("regex 无效: %w", err)
		}
	}
	return &s, nil
}
