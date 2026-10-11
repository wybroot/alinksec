package baseline

const pamQualityReference = "minlen>=12,minclass>=3,credits<=0,enforcing=1,enforce_for_root=1,use_authtok=1"

const pamLengthReference = "minlen>=8,credits<=0,enforcing=1,enforce_for_root=1,use_authtok=1"

const pamSecureTTYReference = "first_auth=required|requisite:securetty,noconsole=1,ttys=nonempty_subset(tty1..tty6)"
