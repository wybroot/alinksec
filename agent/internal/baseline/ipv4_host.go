package baseline

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const ipv4HostTarget = "/proc/sys/net/ipv4"
const ipv4HostRolePath = "/etc/alinksec/ipv4-host-role"
const ipv4HostRole = "non-router-symmetric\n"
const ipv4HostMaxInterfaces = 16

var ipv4HostReferences = map[string]string{
	"rp_filter":  "role=non-router-symmetric,default_effective=1,interfaces_effective=1",
	"forwarding": "role=non-router-symmetric,ip_forward=0,all/default/interfaces_forwarding=0",
}
var ipv4HostInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,14}$`)

func validIPv4Host(cs *CheckSpec) bool {
	return cs.Type == "linux_ipv4_host" && cs.Target == ipv4HostTarget && cs.Operator == "eq" &&
		ipv4HostReferences[cs.Option] != "" && cs.Expected == ipv4HostReferences[cs.Option]
}

type ipv4HostValues struct{ RPFilter, Forwarding int }
type ipv4HostSnapshot struct {
	Namespace  string
	IPForward  int
	Interfaces map[string]ipv4HostValues // all and default are included; no interface is skipped.
	Identities map[string]string         // descriptor identities detect replacement and renaming.
}

func ipv4HostPrefix(option string) string {
	return "scope=current-netns-ipv4-host option=" + option + " role=non-router-symmetric role_source=" + ipv4HostRolePath +
		" routing_state=unverified packet_enforcement_state=unverified persistence_state=unverified other_netns_state=unverified snapshot_state=non_atomic "
}

// The role is an administrator assertion, never inferred from a sysctl value.
// Both observations and the role recheck share the caller's deadline.
func observeIPv4Host(ctx context.Context, cs *CheckSpec, read func() (ipv4HostSnapshot, error), stableRole func() error) ItemResult {
	failure := func(err error) ItemResult {
		return ItemResult{Error: true, Actual: ipv4HostPrefix(cs.Option), Message: err.Error()}
	}
	var first ipv4HostSnapshot
	for i := 0; i < 2; i++ {
		if err := ctx.Err(); err != nil {
			return failure(fmt.Errorf("IPv4读取超过共同截止时间"))
		}
		snapshot, err := read()
		if err != nil {
			return failure(err)
		}
		result := evaluateIPv4Host(cs.Option, snapshot)
		if result.Error {
			return result
		}
		if i == 0 {
			first = snapshot
		} else if !reflect.DeepEqual(first, snapshot) {
			return failure(fmt.Errorf("IPv4参数、接口集合、路径或网络命名空间在读取期间变化"))
		}
	}
	if err := stableRole(); err != nil {
		return failure(err)
	}
	if ctx.Err() != nil {
		return failure(fmt.Errorf("IPv4读取超过共同截止时间"))
	}
	return evaluateIPv4Host(cs.Option, first)
}

func evaluateIPv4Host(option string, s ipv4HostSnapshot) ItemResult {
	prefix := ipv4HostPrefix(option)
	failure := func(message string) ItemResult { return ItemResult{Error: true, Actual: prefix, Message: message} }
	all, allOK := s.Interfaces["all"]
	_, defaultOK := s.Interfaces["default"]
	if ipv4HostReferences[option] == "" || s.Namespace == "" || !allOK || !defaultOK || len(s.Interfaces) < 3 || len(s.Interfaces) > ipv4HostMaxInterfaces+2 || s.IPForward < 0 || s.IPForward > 1 {
		return failure("IPv4命名空间、接口集合或参数不完整、超限或未支持")
	}
	if s.IPForward != all.Forwarding {
		return failure("ip_forward与all.forwarding别名值不一致")
	}
	var names []string
	for name, v := range s.Interfaces {
		if !ipv4HostInterfaceName.MatchString(name) || v.RPFilter < 0 || v.RPFilter > 2 || v.Forwarding < 0 || v.Forwarding > 1 {
			return failure("IPv4接口名称或参数值未支持")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	passed := true
	if option == "forwarding" {
		passed = s.IPForward == 0
	}
	var rows []string
	for _, name := range names {
		v := s.Interfaces[name]
		effective := max(all.RPFilter, v.RPFilter)
		if option == "rp_filter" {
			// all is combined with each real interface and the future default;
			// all=0 with every interface/default=1 is a valid strict reference.
			if name != "all" && effective != 1 {
				passed = false
			}
		} else if v.Forwarding != 0 {
			passed = false
		}
		rows = append(rows, fmt.Sprintf("%s:rp=%d,effective=%d,fwd=%d", name, v.RPFilter, effective, v.Forwarding))
	}
	actual := fmt.Sprintf("%snetns=%s ip_forward=%d interfaces=%d values=[%s]", prefix, s.Namespace, s.IPForward, len(names)-2, strings.Join(rows, ";"))
	message := ""
	if !passed {
		message = "当前IPv4参数未满足已声明非路由/对称路由主机的完整参考"
	}
	return ItemResult{Passed: passed, Actual: actual, Message: message}
}
