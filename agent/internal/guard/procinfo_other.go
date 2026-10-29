//go:build !linux

package guard

func inspectProcessContainer(pid int32) (bool, string) {
	return false, ""
}

func inspectProcessNetwork(pid int32) (string, []procNetConn) {
	return "unavailable", nil
}
