//go:build linux

package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// nologinShells 这些 shell 表示账户禁止交互登录
var nologinShells = map[string]bool{
	"/bin/false": true, "/usr/bin/false": true,
	"/sbin/nologin": true, "/usr/sbin/nologin": true,
	"/bin/sync": true, "/sbin/halt": true, "/usr/sbin/halt": true,
	"/sbin/shutdown": true, "/usr/sbin/shutdown": true,
}

var readAccountFile = os.ReadFile

// collectAccounts Linux 账户：/etc/passwd 解析 + /etc/shadow 口令状态（需 root，Agent 以 root 运行）。
// 风险判定（与弱口令检测规则一致，无在线爆破）：
//   - UID=0 且非 root → 特权克隆账户；
//   - 可信口令字段为空字符串且 shell 允许交互 → 空口令风险（不证明认证成功）。
func collectAccounts(snap *pb.RptAssetSnapshot) {
	passwd, err := readAccountFile("/etc/passwd")
	if err != nil {
		collectionStatus(snap, "accounts", pb.AssetCollection_FAILED, "account_read_failed")
		return
	}
	shadow, shadowErr := loadShadow()

	accounts := make([]*pb.AccountInfo, 0)
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(passwd), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 || f[0] == "" || strings.ContainsAny(line, "\x00\r") || seen[f[0]] {
			collectionStatus(snap, "accounts", pb.AssetCollection_FAILED, "account_parse_failed")
			return
		}
		name := f[0]
		seen[name] = true
		uid, uidErr := strconv.ParseUint(f[2], 10, 32)
		gid, gidErr := strconv.ParseUint(f[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			collectionStatus(snap, "accounts", pb.AssetCollection_FAILED, "account_parse_failed")
			return
		}
		shell := f[6]
		// An empty shell selects the system default (/bin/sh); it does not
		// disable login. Only x delegates the password field to shadow(5).
		loginEnabled := !nologinShells[shell]
		password, known := f[1], true
		if password == "x" {
			password, known = shadow[name]
			if shadowErr != nil {
				collectionStatus(snap, "accounts", pb.AssetCollection_PARTIAL, "shadow_unreadable")
			} else if !known {
				collectionStatus(snap, "accounts", pb.AssetCollection_PARTIAL, "shadow_entry_missing")
			}
		}

		risky, reason := false, ""
		switch {
		case uid == 0 && name != "root":
			risky, reason = true, "UID=0 的非 root 账户"
		case loginEnabled && known && password == "":
			risky, reason = true, "空口令账户"
		}

		accounts = append(accounts, &pb.AccountInfo{
			Name:         name,
			Uid:          uint32(uid),
			Gid:          uint32(gid),
			Shell:        shell,
			LoginEnabled: loginEnabled,
			Risky:        risky,
			RiskyReason:  reason,
		})
	}
	// Publish only a fully parsed passwd inventory. A malformed later row must
	// not turn an incomplete list into a successful replacement on the server.
	snap.Accounts = accounts
}

// loadShadow 读取口令哈希字段：name → hash（"!" / "*" / "!!" 不等同于空口令）。
func loadShadow() (map[string]string, error) {
	m := map[string]string{}
	data, err := readAccountFile("/etc/shadow")
	if err != nil {
		return m, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 9 || f[0] == "" || strings.ContainsAny(line, "\x00\r") {
			return nil, fmt.Errorf("invalid shadow account data")
		}
		if _, duplicate := m[f[0]]; duplicate {
			return nil, fmt.Errorf("ambiguous shadow account data")
		}
		m[f[0]] = f[1]
	}
	return m, nil
}
