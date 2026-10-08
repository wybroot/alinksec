package baseline

const aptPackageVersion = "2.8.3"
const aptPolicyReference = "apt/apt-get:AllowUnauthenticated=false,Force-Yes=false"

func validAPTPolicy(cs *CheckSpec) bool {
	return cs.Type == "apt_install_policy" && cs.Target == "/etc/apt" && cs.Operator == "eq" && cs.Expected == aptPolicyReference
}
