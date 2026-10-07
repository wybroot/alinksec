package baseline

// Fixed reference paths and policies; package input cannot widen the scope.
func logMetadataPolicy(target string) (perm, group string) {
	switch target {
	case "/var/log/audit":
		return "0700", "0"
	case "/var/log/btmp":
		return "0660", "utmp"
	case "/var/log/wtmp":
		return "0664", "utmp"
	}
	return "", ""
}
