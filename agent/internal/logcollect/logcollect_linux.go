//go:build linux

package logcollect

import "time"

// pollInterval Linux：secure 日志轮询周期
func pollInterval() time.Duration { return 5 * time.Second }

// pollOnce Linux：tail 登录日志（RHEL 系 secure，Debian 系 auth.log，都存在则双采）
func (c *Collector) pollOnce() {
	c.tailFile("/var/log/secure", "secure")
	c.tailFile("/var/log/auth.log", "secure")
}
