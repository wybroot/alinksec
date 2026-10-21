package scap

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alinksec/alinksec-agent/internal/configguard"
)

type runtimeFile struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}
type runtimeManifest struct {
	SchemaVersion int           `json:"schemaVersion"`
	Engine        string        `json:"engine"`
	Version       string        `json:"version"`
	Platform      string        `json:"platform"`
	Executable    string        `json:"executable"`
	Files         []runtimeFile `json:"files"`
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// Only pinned files enter the disposable executable directory. Unlisted
// modules, content and loader hooks in the installation are never inherited.
func cloneRuntime(ctx context.Context, cfg Config, destination string) (string, error) {
	data, err := configguard.ReadFile(filepath.Join(cfg.RuntimeDir, "alinksec-runtime.json"), 1<<20)
	if err != nil {
		return "", issue("scap_runtime_unavailable")
	}
	if Digest(data) != cfg.RuntimeSHA256 {
		return "", issue("scap_runtime_changed")
	}
	var manifest runtimeManifest
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF || manifest.SchemaVersion != 1 || manifest.Engine != "SCC" || manifest.Version != "5.12" || manifest.Platform != runtime.GOOS+"-"+runtime.GOARCH || len(manifest.Files) == 0 || len(manifest.Files) > 4096 {
		return "", issue("scap_config_invalid")
	}
	executable := "cscc"
	if runtime.GOOS == "windows" {
		executable = "cscc.exe"
	}
	if manifest.Executable != executable {
		return "", issue("scap_config_invalid")
	}
	seen := map[string]bool{}
	folded := map[string]bool{}
	var total int64
	for _, file := range manifest.Files {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		fold := strings.ToLower(file.Path)
		if !safePath(file.Path) || seen[file.Path] || folded[fold] || strings.HasPrefix(file.Path, "Resources/Content/") || file.Size < 0 || file.Size > 128<<20 || !validHash(file.SHA256) {
			return "", issue("scap_config_invalid")
		}
		seen[file.Path] = true
		folded[fold] = true
		total += file.Size
		if total > 512<<20 {
			return "", issue("scap_resource_limit")
		}
		contents, err := configguard.ReadFile(filepath.Join(cfg.RuntimeDir, filepath.FromSlash(file.Path)), int(file.Size))
		if err != nil || int64(len(contents)) != file.Size || Digest(contents) != file.SHA256 {
			return "", issue("scap_runtime_changed")
		}
		out := filepath.Join(destination, filepath.FromSlash(file.Path))
		if os.MkdirAll(filepath.Dir(out), 0700) != nil {
			return "", issue("scap_worker_failed")
		}
		mode := os.FileMode(0600)
		if file.Executable || file.Path == executable {
			mode = 0700
		}
		if os.WriteFile(out, contents, mode) != nil {
			return "", issue("scap_worker_failed")
		}
	}
	if !seen[executable] || !seen["options.xml"] {
		return "", issue("scap_config_invalid")
	}
	return filepath.Join(destination, executable), nil
}

// Rewrite only the engine's trusted options template, never imported XML.
// SCC may persist its private content checksum state between install and scan.
func configureRuntime(directory, reports string, seconds int) error {
	name := filepath.Join(directory, "options.xml")
	data, err := os.ReadFile(name)
	if err != nil || len(data) > 1<<20 {
		return issue("scap_config_invalid")
	}
	settings := map[string]string{
		"downloadExternalFiles": "0", "appCheckForUpdates": "0", "contentCheckForUpdates": "0", "appUpdateURL": "", "contentRepository": "",
		"ignoreCPEOVALResults": "0", "saveResultsForNotApplicableContent": "1", "answerOCILwithSCAP": "0",
		"validateContentOnInstall": "1", "validateContent": "1", "validateDigitalSignature": "0", "failOnXMLDSig": "0", "contentDevModeSkipValidation": "0",
		"reviewType": "local", "newInstall": "0", "filterSCAPContentPerFamily": "0", "sharedOptions": "1", "customPathLocal": reports,
		"keepXCCDFXML": "1", "keepOVALXML": "0", "keepOCILXML": "0", "keepCPEXML": "0", "keepARFXML": "0", "saveDISACKL": "0", "saveDISACKLB": "0",
		"allSettingsHTMLReport": "0", "nonComplianceHTMLReport": "0", "enableScanSessionDB": "0", "enableSummaryViewer": "0",
		"maxOVALCollectedItemsPerXCCDFResult": "0", "maskPasswords": "1", "itemCreationThresholdEnabled": "1", "itemCreationThreshold": "10000", "externalCmdTimeout": "15",
	}
	_ = seconds // Wall time and process budgets are enforced outside the engine.
	clear := map[string]bool{"contents": true, "ovalContents": true, "ocilContents": true}
	d := xml.NewDecoder(bytes.NewReader(data))
	var output bytes.Buffer
	e := xml.NewEncoder(&output)
	depth := 0
	seen := map[string]bool{}
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return issue("scap_config_invalid")
		}
		if start, ok := token.(xml.StartElement); ok {
			depth++
			if depth == 2 {
				value, replace := settings[start.Name.Local]
				if replace || clear[start.Name.Local] {
					if seen[start.Name.Local] {
						return issue("scap_config_invalid")
					}
					seen[start.Name.Local] = true
					if d.Skip() != nil {
						return issue("scap_config_invalid")
					}
					if e.EncodeToken(start) != nil || e.EncodeToken(xml.CharData(value)) != nil || e.EncodeToken(start.End()) != nil {
						return issue("scap_config_invalid")
					}
					depth--
					continue
				}
			}
		}
		if _, ok := token.(xml.EndElement); ok {
			depth--
		}
		if e.EncodeToken(token) != nil {
			return issue("scap_config_invalid")
		}
	}
	if e.Flush() != nil {
		return issue("scap_config_invalid")
	}
	// Missing settings must not silently fall back to internet access or another
	// output location. The pinned distribution is required to expose them all.
	for key := range settings {
		if !seen[key] {
			return issue("scap_config_invalid")
		}
	}
	for key := range clear {
		if !seen[key] {
			return issue("scap_config_invalid")
		}
	}
	if os.MkdirAll(filepath.Join(directory, "Resources", "Content"), 0700) != nil || os.MkdirAll(reports, 0700) != nil || os.WriteFile(name, output.Bytes(), 0600) != nil {
		return issue("scap_worker_failed")
	}
	return nil
}

type issue string

func (e issue) Error() string { return string(e) }
func Code(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "scap_timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "scap_cancelled"
	}
	var code issue
	if errors.As(err, &code) {
		return string(code)
	}
	// Parsing errors are deliberately fixed codes, never host values or paths.
	if strings.HasPrefix(err.Error(), "scap_") {
		return err.Error()
	}
	return "scap_worker_failed"
}
