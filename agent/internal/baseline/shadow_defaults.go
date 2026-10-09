package baseline

const shadowDefaultsTarget = "/etc/login.defs"
const shadowMaxReference = "max_days=1..90,min_days<=max_days"
const shadowWarnReference = "warn_days=7..14,warn_days<=max_days"

func validShadowDefaults(s *CheckSpec) bool {
	return s.Type == "shadow_account_defaults" && s.Target == shadowDefaultsTarget && s.Operator == "eq" &&
		(s.Option == "max_days" && s.Expected == shadowMaxReference || s.Option == "warn_days" && s.Expected == shadowWarnReference)
}
