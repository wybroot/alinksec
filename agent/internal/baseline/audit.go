package baseline

func auditReference(option string) string {
	if option == "enabled" {
		return "enabled=1|2"
	}
	if option == "identity_watches" {
		return "enabled=1|2,always_exit_all,passwd_shadow_group_gshadow=wa"
	}
	return ""
}
