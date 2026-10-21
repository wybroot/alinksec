package baseline

// These are product policy references, not numerical thresholds prescribed by
// GB/T 22239. Native probes collect local-machine evidence; domain fine-grained
// policies, application accounts and remote-session behavior need review too.
var windowsSecurityReferences = map[string]string{
	"password_length":  "minimum_length>=12",
	"password_age":     "maximum_age=1..90d,minimum_age=1..maximum_age",
	"password_history": "history>=5",
	"lockout":          "threshold=1..5,duration>=900s,reset>=900s,reset<=duration",
	"audit_logon":      "success+failure",
	"audit_account":    "success+failure",
	"audit_policy":     "success+failure",
	"audit_integrity":  "success+failure",
	"rdp_nla":          "UserAuthentication=1",
	"rdp_tls":          "SecurityLayer=2,MinEncryptionLevel>=3",
	"ntlm":             "LmCompatibilityLevel=5",
	"idle_timeout":     "InactivityTimeoutSecs=1..900",
	"smb1":             "SMB1Protocol=Disabled|DisabledWithPayloadRemoved",
}

const windowsSMB1Query = `powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; $feature = @(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop); if ($feature.Count -ne 1) { throw 'Expected SMB1Protocol feature' }; $feature[0].State.ToString()"`

func validWindowsSecurity(s *CheckSpec) bool {
	ref, ok := windowsSecurityReferences[s.Option]
	return ok && s.Target == "local-machine" && s.Operator == "eq" && s.Expected == ref
}
