package baseline

func pamLimitsReference(option string) string {
	switch option {
	case "core":
		return "default_and_explicit_root_soft=0,hard=0"
	case "nofile":
		return "default_and_explicit_root_soft=1024..65536,hard=1024..65536"
	case "nproc":
		return "default_and_explicit_root_soft=1..4096,hard=1..4096"
	}
	return ""
}

func validPAMLimits(cs *CheckSpec) bool {
	return cs.Type == "pam_limits" && cs.Target == "/etc/pam.d/login" && cs.Operator == "eq" &&
		pamLimitsReference(cs.Option) != "" && cs.Expected == pamLimitsReference(cs.Option)
}
