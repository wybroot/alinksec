//go:build linux

package baseline

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// checkFilePerm Linux：stat 元数据 + /etc/passwd、/etc/group 名称解析
func checkFilePerm(cs *CheckSpec) ItemResult {
	fi, err := os.Stat(cs.Target)
	if err != nil {
		return ItemResult{Passed: false, Actual: cs.Target, Message: "stat 失败: " + err.Error()}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ItemResult{Passed: false, Message: "无法获取文件元数据"}
	}
	mode := fmt.Sprintf("%04o", st.Mode&07777)
	owner := lookupName(passwdNames(), int(st.Uid))
	group := lookupName(groupNames(), int(st.Gid))
	actual := fmt.Sprintf("mode=%s owner=%s group=%s", mode, owner, group)

	if cs.Perm != "" && cs.Perm != mode {
		return ItemResult{Passed: false, Actual: actual,
			Message: fmt.Sprintf("权限 %s 不等于要求值 %s", mode, cs.Perm)}
	}
	if cs.Owner != "" && cs.Owner != owner {
		return ItemResult{Passed: false, Actual: actual,
			Message: fmt.Sprintf("属主 %s 不等于要求值 %s", owner, cs.Owner)}
	}
	if cs.Group != "" && cs.Group != group {
		return ItemResult{Passed: false, Actual: actual,
			Message: fmt.Sprintf("属组 %s 不等于要求值 %s", group, cs.Group)}
	}
	return ItemResult{Passed: true, Actual: actual}
}

// passwdNames uid → 用户名（file_perm 取证用；读取失败返回空表）
func passwdNames() map[int]string {
	m := map[int]string{}
	if lines, err := readLines("/etc/passwd"); err == nil {
		for _, l := range lines {
			f := strings.Split(l, ":")
			if len(f) >= 3 {
				if uid, err := strconv.Atoi(f[2]); err == nil {
					m[uid] = f[0]
				}
			}
		}
	}
	return m
}

// groupNames gid → 组名
func groupNames() map[int]string {
	m := map[int]string{}
	if lines, err := readLines("/etc/group"); err == nil {
		for _, l := range lines {
			f := strings.Split(l, ":")
			if len(f) >= 3 {
				if gid, err := strconv.Atoi(f[2]); err == nil {
					m[gid] = f[0]
				}
			}
		}
	}
	return m
}

func lookupName(m map[int]string, id int) string {
	if n, ok := m[id]; ok {
		return n
	}
	return strconv.Itoa(id)
}
