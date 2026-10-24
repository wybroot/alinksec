//go:build !windows

package filetrace

func matchPath(path string) string { return cleanPath(path) }
