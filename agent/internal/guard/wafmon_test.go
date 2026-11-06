package guard

import (
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/proto"
)

func TestParseModsecAuditLines(t *testing.T) {
	// Sample JSON audit log from ModSecurity v3 / Coraza
	logContent := `{
		"transaction": {
			"client_ip": "198.51.100.88",
			"time_stamp": "Fri Nov 06 12:00:00 2026",
			"request": {
				"method": "POST",
				"uri": "/api/users",
				"headers": {
					"User-Agent": "sqlmap/1.6"
				}
			},
			"response": {
				"http_code": 403
			},
			"messages": [
				{
					"message": "SQL Injection Attack: Stacked Queries",
					"details": {
						"ruleId": "942100",
						"severity": "2",
						"data": "1' UNION SELECT 1,2,3",
						"tags": ["attack-sqli", "OWASP_CRS"]
					}
				}
			]
		}
	}`

	lines := []*proto.LogLine{
		{
			Ts:      time.Now().UnixMilli(),
			Content: logContent,
		},
	}

	events := parseModsecAuditLines(lines)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.RuleId != "CRS-942100" {
		t.Errorf("expected RuleId 'CRS-942100', got %s", ev.RuleId)
	}
	if ev.Type != "web_attack" {
		t.Errorf("expected Type 'web_attack', got %s", ev.Type)
	}
	if ev.SrcIp != "198.51.100.88" {
		t.Errorf("expected SrcIp '198.51.100.88', got %s", ev.SrcIp)
	}
	if ev.ActionTaken != "blocked" {
		t.Errorf("expected ActionTaken 'blocked', got %s", ev.ActionTaken)
	}
	if ev.Severity != proto.Severity_SEV_CRITICAL {
		t.Errorf("expected Severity_SEV_CRITICAL, got %v", ev.Severity)
	}
}
