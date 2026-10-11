package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func agentRuntimeDefinition(option string) string {
	reference := agentChannelReference
	if option == "hash_inventory" {
		reference = agentSignatureReference
	}
	raw, _ := json.Marshal(map[string]any{"type": "agent_runtime", "target": "current-agent", "option": option, "operator": "eq", "expected": reference, "timeout_ms": 1000})
	return string(raw)
}
func TestAgentRuntimeDefinitionAndMissingContext(t *testing.T) {
	for _, option := range []string{"channel", "hash_inventory"} {
		raw := agentRuntimeDefinition(option)
		if _, err := ParseCheck(raw); err != nil {
			t.Fatal(err)
		}
		r := Run("missing-context", []*pb.BaselineCheckSpec{{ItemId: "self-evidence", Check: raw}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if len(r.Items) != 1 || r.Items[0].GetItemId() != "self-evidence" || r.Items[0].GetExecutionStatus() != "error" {
			t.Fatal(r)
		}
		for _, field := range []string{"cmd", "connection", "path", "workdir", "process", "pid", "max_age", "regex"} {
			var doc map[string]any
			json.Unmarshal([]byte(raw), &doc)
			doc[field] = nil
			bad, _ := json.Marshal(doc)
			if _, err := ParseCheck(string(bad)); err == nil {
				t.Fatal(field)
			}
		}
		for _, changed := range []string{strings.Replace(raw, "current-agent", "other-agent", 1), strings.Replace(raw, "\"eq\"", "\"contains\"", 1), strings.Replace(raw, "1000", "0", 1)} {
			if _, err := ParseCheck(changed); err == nil {
				t.Fatal(changed)
			}
		}
	}
}

func TestAgentChannelCurrentSessionAndAgeBoundaries(t *testing.T) {
	now := time.Now()
	good := ChannelObservation{Session: 7, Active: true, LastSend: now.Add(-time.Second), LastReceive: now.Add(-time.Second)}
	cs, _ := ParseCheck(agentRuntimeDefinition("channel"))
	for _, tc := range []struct {
		name                 string
		change               func(*ChannelObservation)
		pass, executionError bool
	}{
		{"current", func(*ChannelObservation) {}, true, false},
		{"exact_age", func(v *ChannelObservation) { v.LastSend = now.Add(-60 * time.Second) }, true, false},
		{"stale", func(v *ChannelObservation) { v.LastSend = now.Add(-60*time.Second - time.Nanosecond) }, false, false},
		{"inactive", func(v *ChannelObservation) { v.Active = false }, false, false},
		{"no_receive", func(v *ChannelObservation) { v.LastReceive = time.Time{} }, false, false},
		{"no_session", func(v *ChannelObservation) { v.Session = 0 }, false, true},
		{"future", func(v *ChannelObservation) { v.LastReceive = now.Add(time.Nanosecond) }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := good
			tc.change(&value)
			r := observeAgentChannel(cs, func(context.Context) (ChannelObservation, error) { return value, nil }, func() time.Time { return now })
			if r.Passed != tc.pass || r.Error != tc.executionError {
				t.Fatal(r)
			}
		})
	}
	for _, kind := range []string{"session", "disconnect", "regression", "failure", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			r := observeAgentChannel(cs, func(ctx context.Context) (ChannelObservation, error) {
				calls++
				value := good
				if calls == 2 {
					switch kind {
					case "session":
						value.Session++
					case "disconnect":
						value.Active = false
					case "regression":
						value.LastSend = value.LastSend.Add(-time.Second)
					case "failure":
						return value, fmt.Errorf("SECRET_ENDPOINT_TOKEN")
					case "deadline":
						<-ctx.Done()
						return value, ctx.Err()
					}
				}
				return value, nil
			}, func() time.Time { return now })
			if !r.Error || r.Passed || strings.Contains(r.Actual+r.Message, "SECRET_ENDPOINT_TOKEN") {
				t.Fatal(r)
			}
		})
	}
}
