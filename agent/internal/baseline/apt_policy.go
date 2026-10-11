package baseline

const aptPackageVersion = "2.8.3"
const aptPolicyReference = "apt/apt-get:AllowUnauthenticated=false,Force-Yes=false"
const aptSourcesReference = "apt/apt-get:AllowInsecureRepositories=false,AllowWeakRepositories=false,AllowDowngradeToInsecureRepositories=false;sources:Trusted!=yes,allow-insecure=false,allow-weak=false,allow-downgrade-to-insecure=false,Signed-By=explicit-keyring-files"

func validAPTPolicy(cs *CheckSpec) bool {
	return cs.Type == "apt_install_policy" && cs.Target == "/etc/apt" && cs.Operator == "eq" && cs.Expected == aptPolicyReference
}

func validAPTSources(cs *CheckSpec) bool {
	return cs.Type == "apt_sources_policy" && cs.Target == "/etc/apt" && cs.Operator == "eq" && cs.Expected == aptSourcesReference
}
