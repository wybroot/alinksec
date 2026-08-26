//go:build linux

package guard

import (
	"fmt"
	"os/exec"
	"strings"
)

/* Linux 隔离：iptables 专用链 ALINKSEC_ISO（lo / 已建连 / server IP 放行，其余丢弃），
 * INPUT+OUTPUT 首位挂载。恢复时反向清除。nftables 兼容走 iptables-nft。 */

const isoChain = "ALINKSEC_ISO"

func runIpt(args ...string) error {
	cmd := exec.Command("iptables", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		// nft-only 系统：尝试 iptables-nft 后端
		cmd2 := exec.Command("iptables-nft", args...)
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("iptables %v: %v / %v", args, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}
	return nil
}

// isolatePlatform Linux 隔离：建链 + 放行 server + 挂载 INPUT/OUTPUT
func isolatePlatform(serverIP string) error {
	// 幂等：先清理可能残留的旧挂载
	_ = runIpt("-D", "INPUT", "-j", isoChain)
	_ = runIpt("-D", "OUTPUT", "-j", isoChain)
	_ = runIpt("-F", isoChain)
	_ = runIpt("-X", isoChain)

	if err := runIpt("-N", isoChain); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}
	rules := [][]string{
		{"-A", isoChain, "-i", "lo", "-j", "RETURN"}, // 本机回环
		{"-A", isoChain, "-o", "lo", "-j", "RETURN"},
		{"-A", isoChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"},
	}
	if serverIP != "" {
		rules = append(rules,
			[]string{"-A", isoChain, "-s", serverIP, "-j", "RETURN"},
			[]string{"-A", isoChain, "-d", serverIP, "-j", "RETURN"})
	}
	rules = append(rules,
		[]string{"-A", isoChain, "-j", "DROP"},
		[]string{"-I", "INPUT", "-j", isoChain},
		[]string{"-I", "OUTPUT", "-j", isoChain})
	for _, r := range rules {
		if err := runIpt(r...); err != nil {
			return err
		}
	}
	return nil
}

// restorePlatform 恢复网络
func restorePlatform() error {
	_ = runIpt("-D", "INPUT", "-j", isoChain)
	_ = runIpt("-D", "OUTPUT", "-j", isoChain)
	_ = runIpt("-F", isoChain)
	return runIpt("-X", isoChain)
}
