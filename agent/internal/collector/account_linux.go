//go:build linux

package collector

import (
	"os"
	"strconv"
	"strings"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// nologinShells 这些 shell 表示账户禁止交互登录
var nologinShells = map[string]bool{
	"": true, "/bin/false": true, "/usr/bin/false": true,
	"/sbin/nologin": true, "/usr/sbin/nologin": true,
	"/bin/sync": true, "/sbin/halt": true, "/usr/sbin/halt": true,
	"/sbin/shutdown": true, "/usr/sbin/shutdown": true,
}

// collectAccounts Linux 账户：/etc/passwd 解析 + /etc/shadow 口令状态（需 root，Agent 以 root 运行）。
// 风险判定（与弱口令检测规则一致，无在线爆破）：
//   - UID=0 且非 root → 特权克隆账户；
//   - shadow 口令字段为空字符串 → 空口令可登录。
func collectAccounts(snap *pb.RptAssetSnapshot) {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	shadow := loadShadow()

	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		name := f[0]
		uid, _ := strconv.ParseUint(f[2], 10, 32)
		gid, _ := strconv.ParseUint(f[3], 10, 32)
		shell := f[6]
		loginEnabled := !nologinShells[shell]

		risky, reason := false, ""
		switch {
		case uid == 0 && name != "root":
			risky, reason = true, "UID=0 的非 root 账户"
		case loginEnabled && shadow[name] == "":
			risky, reason = true, "空口令账户"
		}

		snap.Accounts = append(snap.Accounts, &pb.AccountInfo{
			Name:        name,
			Uid:         uint32(uid),
			Gid:         uint32(gid),
			Shell:       shell,
			LoginEnabled: loginEnabled,
			Risky:       risky,
			RiskyReason: reason,
		})
	}
}

// loadShadow 读取口令哈希字段：name → hash（"!" / "*" / "!!" 为锁定或无口令登录，非空口令风险）
func loadShadow() map[string]string {
	m := map[string]string{}
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 2 {
			m[f[0]] = f[1]
		}
	}
	return m
}
