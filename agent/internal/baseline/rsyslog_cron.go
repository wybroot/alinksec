package baseline

const rsyslogPackageVersion = "8.2312.0-3ubuntu9.4"
const rsyslogCronReference = "imuxsock=on,cron.emerg..debug=/var/log/cron.log"

func validRsyslogCron(cs *CheckSpec) bool {
	return cs.Type == "rsyslog_cron_routing" && cs.Target == "/etc/rsyslog.conf" &&
		cs.Operator == "eq" && cs.Expected == rsyslogCronReference
}
