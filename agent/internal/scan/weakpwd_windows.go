//go:build windows

// Windows 弱口令检测（docs/04 §4.2）：
// SAM 哈希不可离线读取（需 SYSTEM 注册表解密，越权风险），不做字典比对；
// M2 仅返回策略型风险（Guest 启用 / 密码永不过期账户）交由基线核查覆盖，
// 此处保持空实现，待 M3 扩展 net user 域策略检测。
package scan

import (
	"log/slog"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func detectWeakPasswords(log *slog.Logger) []*pb.WeakPwdFinding {
	log.Info("Windows 弱口令字典比对不可用（SAM 不可离线读取），跳过")
	return nil
}
