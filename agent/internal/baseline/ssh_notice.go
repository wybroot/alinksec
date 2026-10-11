package baseline

import "regexp"

const sshNoticeTarget = "/etc/ssh/sshd_config"
const sshNoticeBanner = "/etc/issue.net"

var sshNoticeDigest = regexp.MustCompile(`^file=/etc/issue\.net,sha256=[a-f0-9]{64}$`)

func validSSHNotice(s *CheckSpec) bool {
	return s.Type == "sshd_notice" && s.Target == sshNoticeTarget && s.Operator == "eq" &&
		s.Connection.validate() == nil && (s.Option == "usedns" && s.Expected == "no" ||
		s.Option == "banner" && sshNoticeDigest.MatchString(s.Expected))
}
