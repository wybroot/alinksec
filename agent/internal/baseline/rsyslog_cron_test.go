package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func rsyslogCronSpec() *CheckSpec {
	return &CheckSpec{Type: "rsyslog_cron_routing", Target: "/etc/rsyslog.conf", Operator: "eq", Expected: rsyslogCronReference, TimeoutMs: 1000}
}

func TestRsyslogCronDefinitionBoundary(t *testing.T) {
	valid := map[string]any{"type": "rsyslog_cron_routing", "target": "/etc/rsyslog.conf", "operator": "eq", "expected": rsyslogCronReference}
	for key, value := range map[string]any{"target": "/tmp/rsyslog.conf", "operator": "regex", "expected": "cron.*", "cmd": nil, "option": "cron", "perm": "0640", "owner": "0", "group": "0", "uid_min": 0, "connection": nil} {
		changed := map[string]any{}
		for k, v := range valid {
			changed[k] = v
		}
		changed[key] = value
		raw, _ := json.Marshal(changed)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	raw, _ := json.Marshal(valid)
	cs, err := ParseCheck(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if r := checkRsyslogCron(cs); !r.Error || r.Passed {
			t.Fatalf("Linux type executed on Windows: %+v", r)
		}
	}
}
