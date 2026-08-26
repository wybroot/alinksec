// Package comm 实现 Agent 与服务端的 gRPC 通信：
// 注册（Enroll）、主通道双向流（Channel）、离线队列、指令幂等去重
package comm

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// State Agent 本地持久化状态（工作目录 state.yml）
type State struct {
	AgentID       string `yaml:"agent_id"`
	PolicyVersion string `yaml:"policy_version"`

	// 卸载口令布防（docs/01 §6.1 防恶意卸载）：
	// 平台经 CmdAgentControl.ARM_UNINSTALL 下发，15 分钟内有效，卸载命令一次性消费
	UninstallToken  string `yaml:"uninstall_token,omitempty"`
	UninstallExpire int64  `yaml:"uninstall_expire,omitempty"` // Unix 秒
}

// LoadState 从工作目录读取状态
func LoadState(workDir string) (*State, error) {
	b, err := os.ReadFile(filepath.Join(workDir, "state.yml"))
	if err != nil {
		if os.IsNotExist(err) {
			return &State{}, nil
		}
		return nil, err
	}
	s := &State{}
	if err := yaml.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("解析 state.yml: %w", err)
	}
	return s, nil
}

// Save 原子写回状态文件（先写临时文件再替换，避免断电损坏）
func (s *State) Save(workDir string) error {
	b, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	tmp := filepath.Join(workDir, "state.yml.tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(workDir, "state.yml"))
}

// certPaths 证书落盘路径（0600，设计文档 §6 安全机制）
func certPaths(workDir string) (cert, key, ca string) {
	return filepath.Join(workDir, "certs", "client.crt"),
		filepath.Join(workDir, "certs", "client.key"),
		filepath.Join(workDir, "certs", "ca.crt")
}

// CertsExist 判断是否已完成注册（证书齐备）
func CertsExist(workDir string) bool {
	c, k, a := certPaths(workDir)
	for _, f := range []string{c, k, a} {
		if _, err := os.Stat(f); err != nil {
			return false
		}
	}
	return true
}

// saveCerts 注册成功后持久化证书
func saveCerts(workDir string, certPEM, keyPEM, caPEM []byte) error {
	dir := filepath.Join(workDir, "certs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	c, k, a := certPaths(workDir)
	for f, b := range map[string][]byte{c: certPEM, k: keyPEM, a: []byte(caPEM)} {
		if err := os.WriteFile(f, b, 0600); err != nil {
			return err
		}
	}
	return nil
}
