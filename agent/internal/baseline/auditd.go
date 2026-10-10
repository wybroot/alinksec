package baseline

func auditdReference(option string) string {
	switch option {
	case "local_logging":
		return "local_events=yes,write_logs=yes,log_format=raw|enriched"
	case "keep_logs":
		return "local_logging=1,max_log_file>=1,max_log_file_action=keep_logs"
	case "log_file_metadata":
		return "local_logging=1,regular,mode<=0640,uid=0,gid=declared_numeric_log_group"
	}
	return ""
}
