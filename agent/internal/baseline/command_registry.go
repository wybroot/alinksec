package baseline

// approvedCmdOutput is the complete, versioned command set for the seeded
// Linux baseline. The server may select a check, but it cannot turn baseline
// execution into a generic remote shell: an unrecognized command is rejected
// before a process is created.
var approvedCmdOutput = map[string]struct{}{
	`awk -F: '($2==""){print $1}' /etc/shadow`: {},
	`grep -E "^(lp|sync|shutdown|halt|news|uucp|operator|games|gopher):" /etc/passwd | grep -vE "nologin|false$" | wc -l`: {},
	`awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd`:                                                               {},
	`command -v auditctl >/dev/null 2>&1 && echo yes || echo no`:                                                          {},
	`systemctl is-active auditd 2>/dev/null || echo inactive`:                                                             {},
	`systemctl is-active rsyslog 2>/dev/null || echo inactive`:                                                            {},
	`stat -c %U /var/log/messages 2>/dev/null || echo root`:                                                               {},
	`sysctl -n net.ipv4.tcp_syncookies`:                                                                                   {},
	`sysctl -n net.ipv4.conf.all.accept_redirects`:                                                                        {},
	`sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null || echo 0`:                                                  {},
	`sysctl -n net.ipv4.conf.all.accept_source_route`:                                                                     {},
	`sysctl -n net.ipv4.icmp_echo_ignore_broadcasts`:                                                                      {},
	`sysctl -n net.ipv4.conf.all.rp_filter`:                                                                               {},
	`sysctl -n net.ipv4.conf.all.log_martians`:                                                                            {},
	`sysctl -n net.ipv4.ip_forward`:                                                                                       {},
	`sh -c "(getenforce 2>/dev/null | grep -q Enforcing && echo enabled) || (aa-status --enabled 2>/dev/null && echo enabled) || echo disabled"`:                                            {},
	`find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -newer /etc/passwd 2>/dev/null | wc -l`:                                                                                             {},
	`sh -c "f=/etc/bashrc; [ -f \"$f\" ] || f=/etc/bash.bashrc; grep -E '^\s*umask\s+0(2[27]|07)' \"$f\" >/dev/null 2>&1 && echo yes || echo no"`:                                           {},
	`systemctl list-timers --no-pager 2>/dev/null | grep -c systemd-tmpfiles`:                                                                                                               {},
	`sh -c "findmnt -n /tmp >/dev/null 2>&1 && findmnt -no OPTIONS /tmp | grep -cE 'nosuid|nodev' || echo 1"`:                                                                               {},
	`command -v alinksec-agent >/dev/null 2>&1 && echo yes || echo no`:                                                                                                                      {},
	`sh -c "apt-config dump 2>/dev/null | grep -c AllowUnauthenticated \"1\"" || echo 0`:                                                                                                    {},
	`sh -c "grep -rhE '^(baseurl|deb)\s+\S+' /etc/yum.repos.d/ /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -vcE 'https|file:///|ftp://鍐呯綉|^[[:space:]]*#' || echo 0"`: {},
	`sh -c "systemctl is-active chronyd 2>/dev/null || systemctl is-active ntpd 2>/dev/null || echo inactive"`:                                                                              {},
	`sh -c "grep -hE '^ExecStart=.*sulogin' /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service 2>/dev/null | wc -l"`:                                          {},
	`sh -c "systemctl is-enabled ctrl-alt-del.target 2>/dev/null || echo enabled"`:                                                                                                          {},
}

func isApprovedCmdOutput(command string) bool {
	_, ok := approvedCmdOutput[command]
	return ok
}
