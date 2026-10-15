//go:build linux

package isolation

func testBackends() []string { return []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} }
