//go:build windows

package guard

import (
	"fmt"
	"os/exec"
)

/* Windows 隔离：netsh advfirewall —— server IP 先放行，
 * 再将三 profile 默认策略设为 blockinbound,blockoutbound。
 * 恢复 = 还原默认策略 + 删除放行规则。 */

const isoAllowRule = "AlinkSecIsoAllowServer"

func runNetsh(args ...string) (string, error) {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	return string(out), err
}

// isolatePlatform Windows 隔离
func isolatePlatform(serverIP string) error {
	if serverIP != "" {
		// server 放行（入+出）：保证管控通道存活，可下达 RESTORE
		if _, err := runNetsh("advfirewall", "firewall", "add", "rule",
			"name="+isoAllowRule, "dir=in", "action=allow",
			"remoteip="+serverIP, "profile=any"); err != nil {
			return fmt.Errorf("allow in: %w", err)
		}
		if _, err := runNetsh("advfirewall", "firewall", "add", "rule",
			"name="+isoAllowRule, "dir=out", "action=allow",
			"remoteip="+serverIP, "profile=any"); err != nil {
			return fmt.Errorf("allow out: %w", err)
		}
	}
	for _, p := range []string{"domain", "private", "public"} {
		if _, err := runNetsh("advfirewall", "set", p, "profile",
			"firewallpolicy", "blockinbound,blockoutbound"); err != nil {
			return fmt.Errorf("set profile %s: %w", p, err)
		}
	}
	return nil
}

// restorePlatform 还原默认策略（入站阻断/出站允许）+ 清放行规则
func restorePlatform() error {
	for _, p := range []string{"domain", "private", "public"} {
		_, _ = runNetsh("advfirewall", "set", p, "profile",
			"firewallpolicy", "blockinbound,allowoutbound")
	}
	_, _ = runNetsh("advfirewall", "firewall", "delete", "rule",
		"name="+isoAllowRule)
	return nil
}
