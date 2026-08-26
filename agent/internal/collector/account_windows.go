//go:build windows

package collector

import (
	"github.com/yusufpapurcu/wmi"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// winUserAccount Win32_UserAccount 本地账户映射（WMI DATETIME 字段不直接反序列化，仅取需要的列）
type winUserAccount struct {
	Name     string
	Disabled bool
}

// collectAccounts Windows 本地账户（LocalAccount=TRUE）。
// uid/gid/shell 无对应概念置 0/空；空口令状态 WMI 不可见，risky 恒 false（由弱口令检测任务补充）。
func collectAccounts(snap *pb.RptAssetSnapshot) {
	var dst []winUserAccount
	if err := wmi.Query("SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE", &dst); err != nil {
		return
	}
	for _, u := range dst {
		snap.Accounts = append(snap.Accounts, &pb.AccountInfo{
			Name:         u.Name,
			LoginEnabled: !u.Disabled,
		})
	}
}
