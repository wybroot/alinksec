package baseline

func isIdentityPath(path string) bool {
	return path == "/etc/passwd" || path == "/etc/shadow" || path == "/etc/group" || path == "/etc/gshadow"
}
