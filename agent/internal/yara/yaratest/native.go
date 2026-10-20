package yaratest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/configguard"
	"github.com/alinksec/alinksec-agent/internal/yara"
)

const Marker = "MZ harmless ALINKSEC_NATIVE_YARA_731_NATIVE fixture\n"
const Rules = `import "math"
rule AlinkSec_Native_Marker {
 meta: severity = 4
 strings:
  $text = "ALINKSEC_NATIVE_YARA"
  $hex = { 37 33 31 5F 4E 41 54 49 56 45 }
  $re = /YARA_[0-9]{3}_NATIVE/
 condition: uint16(0) == 0x5a4d and all of them and math.entropy(0,filesize) >= 0.0
}
rule AlinkSec_Secondary {
 meta: severity = 2
 strings: $s = "_731_NATIVE"
 condition: $s and filesize > 32
}`

func Config(t *testing.T, source string) yara.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pinned rules.yar")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return yara.Config{Enabled: true, Realtime: true, RulesFile: path, RulesSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(source))), TimeoutSec: 10}
}
func Native(t *testing.T) (yara.Config, string) {
	t.Helper()
	if yara.Contract() != 1 {
		if os.Getenv("ALINKSEC_YARA_NATIVE_REQUIRED") == "true" {
			t.Fatal("native YARA build required")
		}
		t.Skip("requires -tags nativeyara and statically linked libyara4.5.8")
	}
	cfg := Config(t, Rules)
	client := yara.New(cfg, configguard.ReadFile)
	v, err := client.Probe(context.Background())
	if err != nil || !strings.HasPrefix(v, "YARA 4.5.8/sha256:") {
		t.Fatalf("probe=%q error=%v status=%+v", v, err, client.Status())
	}
	return cfg, v
}
