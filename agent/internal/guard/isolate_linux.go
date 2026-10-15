//go:build linux

package guard

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

/* Linux 隔离：iptables 专用链 ALINKSEC_ISO（lo / 已建连 / server IP 放行，其余丢弃），
 * INPUT+OUTPUT 首位挂载。恢复时反向清除。nftables 兼容走 iptables-nft。 */

const isoChain = "ALINKSEC_ISO"

func runIpt(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "iptables", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		// nft-only 系统：尝试 iptables-nft 后端
		cmd2 := exec.CommandContext(ctx, "iptables-nft", args...)
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("iptables %v: %v / %v", args, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
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
