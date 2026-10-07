package baseline

const cronMetadataReference = "crontab<=0644,cron.d<=0755,all_entries<=0644,uid=0,gid=0"
const cronPackageVersion = "3.0pl1-184ubuntu2"

func validCronMetadata(cs *CheckSpec) bool {
	return cs.Type == "debian_cron_metadata" && cs.Target == "system-tables" &&
		cs.Operator == "eq" && cs.Expected == cronMetadataReference
}
