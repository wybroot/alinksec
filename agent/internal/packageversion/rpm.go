// Package packageversion retains native package identity when querying installed versions.
package packageversion

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var rpmPart = regexp.MustCompile(`^[A-Za-z0-9._+~^]+$`)

// RPM builds a complete epoch:version-release from the separate RPM database fields.
func RPM(epoch, version, release string) (string, error) {
	if epoch == "" || strings.IndexFunc(epoch, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return "", fmt.Errorf("unsupported RPM epoch")
	}
	e, err := strconv.ParseUint(epoch, 10, 32)
	if err != nil || !rpmPart.MatchString(version) || !rpmPart.MatchString(release) {
		return "", fmt.Errorf("unsupported RPM version fields")
	}
	result := strconv.FormatUint(e, 10) + ":" + version + "-" + release
	if len(result) > 255 {
		return "", fmt.Errorf("RPM version exceeds limit")
	}
	return result, nil
}

// RPMIdentity normalizes only the epoch. Other segments must match exactly for repair verification.
func RPMIdentity(value string) (string, error) {
	if value == "" || len(value) > 255 {
		return "", fmt.Errorf("unsupported RPM version")
	}
	epoch, body := "0", value
	if before, after, found := strings.Cut(value, ":"); found {
		epoch, body = before, after
	}
	dash := strings.LastIndexByte(body, '-')
	if dash < 1 || dash == len(body)-1 {
		return "", fmt.Errorf("complete RPM release is required")
	}
	return RPM(epoch, body[:dash], body[dash+1:])
}
