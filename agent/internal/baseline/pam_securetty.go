package baseline

import "regexp"

var secureTTYName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_/.-]{0,249}$`)
