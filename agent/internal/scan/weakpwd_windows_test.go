//go:build windows

package scan

import (
	"context"
	"testing"
)

func TestWindowsWeakPasswordsAreExplicitlyUnsupported(t *testing.T) {
	findings, c := detectWeakPasswords(context.Background(), nil)
	if WeakPasswordContract() != 0 || len(findings) != 0 || c.Status != "unsupported" || len(c.Issues) != 1 || c.Issues[0] != "platform_unsupported" {
		t.Fatal("unsupported platform reported a pass")
	}
}
