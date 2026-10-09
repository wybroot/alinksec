package baseline

const bashPolicyTarget = "/etc"

var bashPolicyReferences = map[string]string{
	"login_timeout":    "TMOUT=1..600,readonly=1,exported=1",
	"login_umask":      "umask=027|077",
	"history_time":     "HISTTIMEFORMAT=%F %T %z ",
	"history_capacity": "HISTSIZE=1000..10000,HISTFILESIZE=1000..10000",
	"nonlogin_umask":   "umask=027|077",
}

func validBashPolicy(s *CheckSpec) bool {
	expected, ok := bashPolicyReferences[s.Option]
	return ok && s.Type == "bash_global_policy" && s.Target == bashPolicyTarget && s.Operator == "eq" && s.Expected == expected
}
