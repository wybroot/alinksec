//go:build windows

package collector

import (
	"strings"

	"github.com/yusufpapurcu/wmi"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// winUserAccount Win32_UserAccount 本地账户映射（WMI DATETIME 字段不直接反序列化，仅取需要的列）。
// PasswordRequired 仅反映 Windows UF_PASSWD_NOTREQD 策略状态，不代表已校验 SAM 口令哈希强度。
type winUserAccount struct {
	Name             string
	Disabled         bool
	PasswordRequired bool
	Lockout          bool
	SID              string
}

var queryWindowsAccounts = defaultQueryWindowsAccounts

func defaultQueryWindowsAccounts() ([]winUserAccount, error) {
	var dst []winUserAccount
	err := wmi.Query("SELECT Name, Disabled, PasswordRequired, Lockout, SID FROM Win32_UserAccount WHERE LocalAccount = TRUE", &dst)
	return dst, err
}

// collectAccounts Windows 本地账户（LocalAccount=TRUE）。
// uid/gid/shell 无对应概念置 0/空；仅当策略明确允许无口令登录时标记风险，完整口令审计仍超出本采集器范围。
func collectAccounts(snap *pb.RptAssetSnapshot) {
	dst, err := queryWindowsAccounts()
	if err != nil {
		collectionStatus(snap, "accounts", pb.AssetCollection_FAILED, "account_read_failed")
		return
	}
	accounts := make([]*pb.AccountInfo, 0, len(dst))
	seen := make(map[string]bool, len(dst))
	for _, u := range dst {
		if strings.TrimSpace(u.Name) == "" || len(u.Name) > 255 || strings.ContainsAny(u.Name, "\x00\r\n") {
			collectionStatus(snap, "accounts", pb.AssetCollection_FAILED, "account_parse_failed")
			return
		}
		key := strings.ToLower(u.Name)
		if seen[key] {
			collectionStatus(snap, "accounts", pb.AssetCollection_FAILED, "account_parse_failed")
			return
		}
		seen[key] = true

		loginEnabled := !u.Disabled
		risky, reason := false, ""
		if loginEnabled && !u.PasswordRequired {
			risky, reason = true, "无需口令即可登录的本地账户"
		}
		accounts = append(accounts, &pb.AccountInfo{
			Name:         u.Name,
			LoginEnabled: loginEnabled,
			Risky:        risky,
			RiskyReason:  reason,
		})
	}
	snap.Accounts = accounts
}
