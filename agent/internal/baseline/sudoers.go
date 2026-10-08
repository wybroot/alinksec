package baseline

const sudoPackageVersion = "1.9.15p5-3ubuntu5.24.04.3"

func sudoersReference(option string) string {
	switch option {
	case "authentication":
		return "authenticate=on,exempt_group=unset,nopasswd_tags=0"
	case "allowed_logging":
		return "log_allowed=on,logfile=/var/log/sudo.log"
	}
	return ""
}

func validSudoers(cs *CheckSpec) bool {
	return cs.Type == "sudoers_policy" && cs.Target == "/etc/sudoers" && cs.Operator == "eq" &&
		sudoersReference(cs.Option) != "" && cs.Expected == sudoersReference(cs.Option)
}
