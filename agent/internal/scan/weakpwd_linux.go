//go:build linux

// 弱口令检测（Linux，docs/04 §4.2 —— 不做在线爆破）：
// 策略型检测（shadow 字段静态分析，不做哈希字典比对）：
//   - system_empty  密码字段为空（任意口令即可登录）
//   - uid0_nonroot  UID=0 非 root 账户（提权残留）
//   - pwd_stale     密码长期未修改（shadow 第3字段距今天数超阈值，默认 90 天）
//
// 说明：哈希离线字典比对（md5crypt/sha-crypt）涉及从零实现 crypt 算法，
// 精度风险高，M2 不做；后续如需可引入成熟第三方库再启用。
// Windows：SAM 不可离线读取，留空实现（M3 策略型检测）。
package scan

import (
	"bufio"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// pwdStaleDays 密码未修改告警阈值（天）
const pwdStaleDays = 90

// nologinShells 非登录 shell 的系统账户，空密码不构成实际登录风险，跳过
var nologinShells = map[string]bool{
	"/sbin/nologin": true, "/usr/sbin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "/bin/sync": true,
}

// detectWeakPasswords 解析 /etc/shadow + /etc/passwd（root 权限）做策略型检测
func detectWeakPasswords(log *slog.Logger) []*pb.WeakPwdFinding {
	type account struct {
		uid   int
		shell string
	}
	passwd := map[string]account{}
	if f, err := os.Open("/etc/passwd"); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			p := strings.Split(s.Text(), ":")
			if len(p) < 7 {
				continue
			}
			uid, _ := strconv.Atoi(p[2])
			passwd[p[0]] = account{uid: uid, shell: p[6]}
		}
	} else {
		log.Error("读取 /etc/passwd 失败", "err", err)
	}

	f, err := os.Open("/etc/shadow")
	if err != nil {
		log.Error("读取 /etc/shadow 失败（agent 需 root 运行）", "err", err)
		return nil
	}
	defer f.Close()

	var findings []*pb.WeakPwdFinding
	now := time.Now()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		p := strings.Split(s.Text(), ":")
		if len(p) < 2 {
			continue
		}
		user, hash := p[0], p[1]
		shell := passwd[user].shell

		if hash == "" && !nologinShells[shell] {
			// 密码字段为空且是可登录 shell → 任意口令即可登录
			findings = append(findings, &pb.WeakPwdFinding{
				Account: user, Type: "system_empty"})
		}
		// 密码长期未修改：第3字段为上次修改距 1970-01-01 的天数
		if len(p) > 2 && p[2] != "" && !nologinShells[shell] {
			if days, err := strconv.Atoi(p[2]); err == nil && days > 0 {
				unused := int(now.Sub(time.Unix(int64(days)*86400, 0)).Hours() / 24)
				if unused > pwdStaleDays {
					findings = append(findings, &pb.WeakPwdFinding{
						Account: user, Type: "pwd_stale",
						Password: strconv.Itoa(unused) + " 天未修改"})
				}
			}
		}
	}
	// UID=0 非 root（提权残留）
	for user, a := range passwd {
		if a.uid == 0 && user != "root" {
			findings = append(findings, &pb.WeakPwdFinding{
				Account: user, Type: "uid0_nonroot"})
		}
	}
	return findings
}
