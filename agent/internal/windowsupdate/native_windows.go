//go:build windows

package windowsupdate

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

//go:embed worker.ps1
var worker string

func ExecutionContract() uint32 { return 1 }

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("WUA output capacity exceeded")
	}
	return b.Buffer.Write(p)
}
func nativeRun(ctx context.Context, r Request) (response, error) { return runScript(ctx, r, worker) }
func runScript(ctx context.Context, r Request, script string) (response, error) {
	var result response
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return result, err
	}
	// Absolute system executable and a static encoded script. Request data enters
	// through JSON stdin and is never interpolated into executable PowerShell.
	chars := utf16.Encode([]rune(script))
	encoded := make([]byte, len(chars)*2)
	for i, c := range chars {
		binary.LittleEndian.PutUint16(encoded[i*2:], c)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	input, _ := json.Marshal(r)
	cmd.Stdin = bytes.NewReader(input)
	out := &limitedBuffer{limit: 2 << 20}
	errs := &limitedBuffer{limit: 8192}
	cmd.Stdout = out
	cmd.Stderr = errs
	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("WUA worker failed: %w", err)
	}
	// The two embedded structs share contract/host_identity/reboot_required; decode
	// independently so neither silently loses these shared fields.
	if json.Unmarshal(out.Bytes(), &result.Snapshot) != nil || json.Unmarshal(out.Bytes(), &result.Outcome) != nil {
		return result, fmt.Errorf("invalid WUA response")
	}
	var detail struct {
		Update *Update `json:"update"`
	}
	_ = json.Unmarshal(out.Bytes(), &detail)
	result.Update = detail.Update
	return result, nil
}
