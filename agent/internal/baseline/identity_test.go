package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestIdentityDefinitionsRejectExpandedExecutionAndImplicitScope(t *testing.T) {
	checks := []string{
		`{"type":"local_identity_file","target":"/etc/passwd","perm":"0644","owner":"0","group":"0","operator":"subset"}`,
		`{"type":"local_accounts","target":"/etc/shadow","option":"empty_password","operator":"eq","expected":"0"}`,
		`{"type":"local_accounts","target":"/etc/passwd","option":"uid0_accounts","operator":"eq","expected":"root"}`,
		`{"type":"local_accounts","target":"/etc/passwd","option":"system_shells","operator":"eq","expected":"0","uid_min":1,"uid_max":999}`,
	}
	for _, raw := range checks {
		if _, err := ParseCheck(raw); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"cmd", "connection", "regex", "path", "allowed_shells"} {
			var doc map[string]any
			json.Unmarshal([]byte(raw), &doc)
			doc[field] = "unreviewed"
			data, _ := json.Marshal(doc)
			if _, err := ParseCheck(string(data)); err == nil {
				t.Fatalf("accepted field %s", field)
			}
		}
	}
	for _, raw := range []string{
		`{"type":"local_identity_file","target":"/etc/passwd-","perm":"0644","owner":"0","group":"0","operator":"subset"}`,
		`{"type":"local_identity_file","target":"/etc/shadow","perm":"644","owner":"0","group":"shadow","operator":"subset"}`,
		`{"type":"local_identity_file","target":"/etc/shadow","perm":"0640","owner":"root","group":"shadow","operator":"subset"}`,
		`{"type":"local_accounts","target":"/etc/passwd","option":"system_shells","operator":"eq","expected":"0"}`,
		`{"type":"local_accounts","target":"/etc/passwd","option":"system_shells","operator":"eq","expected":"0","uid_min":0,"uid_max":999}`,
		`{"type":"local_accounts","target":"/etc/passwd","option":"system_shells","operator":"eq","expected":"0","uid_min":1000,"uid_max":999}`,
		`{"type":"local_accounts","target":"/etc/passwd","option":"system_shells","operator":"eq","expected":"0","uid_min":1,"uid_max":4294967295}`,
		`{"type":"local_accounts","target":"/etc/passwd","option":"uid0_accounts","operator":"eq","expected":"root","uid_min":1}`,
		`{"type":"local_accounts","target":"/etc/shadow","option":"empty_password","operator":"eq","expected":"0","target":"/tmp/shadow"}`,
	} {
		if _, err := ParseCheck(raw); err == nil {
			t.Fatalf("accepted invalid identity definition: %s", raw)
		}
	}
}

func TestIdentityDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows platform boundary")
	}
	for _, kind := range []string{"local_identity_file", "local_accounts"} {
		result := checkLocalIdentity(&CheckSpec{Type: kind})
		if !result.Error || result.Passed {
			t.Fatalf("unsupported Windows check: %+v", result)
		}
	}
}
