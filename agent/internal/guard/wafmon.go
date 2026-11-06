package guard

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/alinksec/alinksec-agent/internal/proto"
)

type modsecAuditRecord struct {
	Transaction struct {
		ClientIP  string `json:"client_ip"`
		TimeStamp string `json:"time_stamp"`
		UniqueId  string `json:"unique_id"`
		Request   struct {
			Method  string            `json:"method"`
			URI     string            `json:"uri"`
			Headers map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int `json:"http_code"`
		} `json:"response"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				RuleID   string   `json:"ruleId"`
				File     string   `json:"file"`
				Data     string   `json:"data"`
				Severity string   `json:"severity"`
				Tags     []string `json:"tags"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
	// Flat fallback
	ClientIP string `json:"client_ip"`
	URI      string `json:"uri"`
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
}

func parseModsecAuditLines(lines []*proto.LogLine) []*proto.RptSecurityEvent {
	var events []*proto.RptSecurityEvent
	for _, l := range lines {
		if l == nil || len(l.Content) == 0 {
			continue
		}
		raw := strings.TrimSpace(l.Content)
		if !strings.HasPrefix(raw, "{") || !strings.HasSuffix(raw, "}") {
			continue
		}
		var rec modsecAuditRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}

		clientIP := rec.Transaction.ClientIP
		if clientIP == "" {
			clientIP = rec.ClientIP
		}
		if clientIP == "" {
			clientIP = "127.0.0.1"
		}

		uri := rec.Transaction.Request.URI
		if uri == "" {
			uri = rec.URI
		}
		method := rec.Transaction.Request.Method
		if method == "" {
			method = "GET"
		}
		httpCode := rec.Transaction.Response.HTTPCode

		action := "alert_only"
		if httpCode == 403 || httpCode == 400 {
			action = "blocked"
		}

		if len(rec.Transaction.Messages) > 0 {
			for _, m := range rec.Transaction.Messages {
				ruleID := m.Details.RuleID
				if ruleID == "" {
					ruleID = "CRS-unknown"
				} else if !strings.HasPrefix(ruleID, "CRS-") {
					ruleID = "CRS-" + ruleID
				}
				ruleName := m.Message
				if ruleName == "" {
					ruleName = "OWASP CRS Web 攻击检出"
				}

				sev := mapModsecSeverity(m.Details.Severity)
				ts := l.Ts
				if ts <= 0 {
					ts = time.Now().UnixMilli()
				}

				detailMap := map[string]any{
					"source":     "modsec_audit_json",
					"client_ip":  clientIP,
					"uri":        uri,
					"method":     method,
					"rule_id":    ruleID,
					"message":    ruleName,
					"match_data": m.Details.Data,
					"http_code":  httpCode,
					"waf_engine": "modsecurity-crs",
					"tags":       m.Details.Tags,
				}
				detailBytes, _ := json.Marshal(detailMap)

				event := &proto.RptSecurityEvent{
					RuleId:      ruleID,
					RuleName:    ruleName,
					Type:        "web_attack",
					Severity:    sev,
					ActionTaken: action,
					SrcIp:       clientIP,
					EventTs:     ts,
					Detail:      string(detailBytes),
					ProcessKey:  "waf:" + clientIP + ":" + ruleID,
				}
				events = append(events, event)
			}
		} else if rec.RuleID != "" || rec.Message != "" {
			ruleID := rec.RuleID
			if ruleID == "" {
				ruleID = "CRS-unknown"
			}
			ruleName := rec.Message
			if ruleName == "" {
				ruleName = "OWASP CRS Web 攻击检出"
			}
			ts := l.Ts
			if ts <= 0 {
				ts = time.Now().UnixMilli()
			}
			detailMap := map[string]any{
				"source":     "modsec_audit_json",
				"client_ip":  clientIP,
				"uri":        uri,
				"method":     method,
				"rule_id":    ruleID,
				"message":    ruleName,
				"waf_engine": "modsecurity-crs",
			}
			detailBytes, _ := json.Marshal(detailMap)
			events = append(events, &proto.RptSecurityEvent{
				RuleId:      ruleID,
				RuleName:    ruleName,
				Type:        "web_attack",
				Severity:    proto.Severity_SEV_HIGH,
				ActionTaken: action,
				SrcIp:       clientIP,
				EventTs:     ts,
				Detail:      string(detailBytes),
				ProcessKey:  "waf:" + clientIP + ":" + ruleID,
			})
		}
	}
	return events
}

func mapModsecSeverity(s string) proto.Severity {
	switch strings.TrimSpace(s) {
	case "0", "EMERGENCY", "1", "ALERT", "2", "CRITICAL":
		return proto.Severity_SEV_CRITICAL
	case "3", "ERROR":
		return proto.Severity_SEV_HIGH
	case "4", "WARNING":
		return proto.Severity_SEV_MEDIUM
	case "5", "NOTICE":
		return proto.Severity_SEV_LOW
	default:
		return proto.Severity_SEV_MEDIUM
	}
}
