//go:build windows

package guard

/* Windows 归因：Restart Manager API 查锁定进程需 CGO/win32 绑定，
 * 一期降级为最近活跃进程启发式（respond.go attributeByRecency）。 */

func attributeByOpenFD(files []string) *suspectProc { return nil }
