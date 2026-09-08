// Package config 负责 Agent 配置加载（agent.yml）
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config Agent 运行配置（工作目录下 agent.yml，可用 --config 覆盖）
type Config struct {
	// 服务端 gRPC 地址（host:port）
	ServerAddr string `yaml:"server_addr"`
	// 注册码（首次安装使用，注册成功后证书落盘即不再依赖）
	EnrollToken string `yaml:"enroll_token"`
	// 心跳间隔（设计文档：10s）
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	// TLS ServerName 覆盖（服务端证书 SAN 不含连接地址时使用）
	ServerNameOverride string `yaml:"server_name_override"`
	// EnrollCAFile is the CA PEM used to verify the server during initial enrollment.
	EnrollCAFile string `yaml:"enroll_ca_file"`
	// 离线队列补传限速（条/秒，设计文档：100）
	DrainRatePerSec int `yaml:"drain_rate_per_sec"`
	// 资产快照采集间隔（默认 6h；服务端 CmdCollectNow 可即时触发）
	CollectInterval time.Duration `yaml:"collect_interval"`
	// Kubernetes 节点名覆盖。为空时使用本机 hostname，只采集调度到该节点的工作负载。
	KubernetesNodeName string `yaml:"kubernetes_node_name"`
	// 勒索诱饵防护（docs/05 §2；空值用平台默认，本地响应不依赖服务端在线）
	Decoy DecoyConfig `yaml:"decoy"`
}

// DecoyConfig 勒索诱饵防护配置（json tag 与平台 policy_json.decoy 段同构，热下发用）
type DecoyConfig struct {
	// 总开关（缺省开启；显式 enabled: false 关闭）
	Enabled *bool `yaml:"enabled" json:"enabled,omitempty"`
	// 响应级别：alert_only / kill / kill_and_isolate（默认 kill_and_isolate）
	Response string `yaml:"response" json:"response,omitempty"`
	// 投放目录（空 = 平台默认：Linux /home /srv /opt；Windows 公共文档/桌面）
	Dirs []string `yaml:"dirs" json:"dirs,omitempty"`
	// 每目录诱饵数（默认 4）
	CountPerDir int `yaml:"count_per_dir" json:"count_per_dir,omitempty"`
	// 排除进程 exe 路径（备份/杀毒/索引类，误报防护）
	ExcludeExes []string `yaml:"exclude_exes" json:"exclude_exes,omitempty"`
	// 加密速率监测窗口秒（默认 10）
	RateWindowSec int `yaml:"rate_window_sec" json:"rate_window_sec,omitempty"`
	// 窗口内写入/重命名文件数阈值（默认 50）
	RateThreshold int `yaml:"rate_threshold" json:"rate_threshold,omitempty"`
	// 扩展名变化率阈值（默认 0.8）
	ExtChangeRatio float64 `yaml:"ext_change_ratio" json:"ext_change_ratio,omitempty"`
	// 速率监测目录树（空 = 同 Dirs）
	WatchTrees []string `yaml:"watch_trees" json:"watch_trees,omitempty"`
}

// Normalize 填充默认值（本地加载与平台策略热下发共用）
func (d *DecoyConfig) Normalize() {
	if d.Enabled == nil {
		t := true
		d.Enabled = &t
	}
	if d.Response == "" {
		d.Response = "kill_and_isolate"
	}
	if d.CountPerDir <= 0 {
		d.CountPerDir = 4
	}
	if d.RateWindowSec <= 0 {
		d.RateWindowSec = 10
	}
	if d.RateThreshold <= 0 {
		d.RateThreshold = 50
	}
	if d.ExtChangeRatio <= 0 {
		d.ExtChangeRatio = 0.8
	}
}

// Load 从文件加载配置并填充默认值
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取配置 %s: %w", path, err)
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("解析配置 %s: %w", path, err)
		}
	}
	// 默认值
	if c.ServerAddr == "" {
		c.ServerAddr = "127.0.0.1:9443"
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 10 * time.Second
	}
	if c.DrainRatePerSec <= 0 {
		c.DrainRatePerSec = 100
	}
	if c.CollectInterval <= 0 {
		c.CollectInterval = 6 * time.Hour
	}
	c.Decoy.Normalize()
	return c, nil
}

// WriteExample install 子命令落盘配置
func WriteExample(path, serverAddr, enrollToken, enrollCAFile string) error {
	c := &Config{ServerAddr: serverAddr, EnrollToken: enrollToken, EnrollCAFile: enrollCAFile}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

// ClearEnrollToken removes the bootstrap credential after the Agent has received its client certificate.
func ClearEnrollToken(path string) error {
	c, err := Load(path)
	if err != nil {
		return err
	}
	c.EnrollToken = ""
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
