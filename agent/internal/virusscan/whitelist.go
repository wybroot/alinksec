package virusscan

import (
	"encoding/json"
	"fmt"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type whitelistEntry struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func loadWhitelist(workDir string) []whitelistEntry {
	data, err := readVirusPolicy(workDir)
	return parseWhitelist(data, err)
}
func parseWhitelist(data []byte, err error) []whitelistEntry {
	if err != nil {
		return nil
	}
	var policy struct {
		Entries []whitelistEntry `json:"virus_whitelist"`
	}
	if json.Unmarshal(data, &policy) != nil {
		return nil
	}
	return policy.Entries
}

func readVirusPolicy(workDir string) ([]byte, error) {
	f, err := os.Open(filepath.Join(workDir, "policy.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("policy exceeds 1MiB")
	}
	return data, err
}
func RealtimePolicy(workDir string) (bool, bool) {
	data, err := readVirusPolicy(workDir)
	return parseRealtimePolicy(data, err)
}
func parseRealtimePolicy(data []byte, err error) (bool, bool) {
	if len(data) == 0 && err == nil {
		return true, true
	}
	if os.IsNotExist(err) {
		return true, true
	}
	if err != nil {
		return false, false
	}
	var p struct {
		Virus *struct {
			Enabled bool   `json:"enabled"`
			Action  string `json:"action"`
		} `json:"virus_realtime"`
	}
	if json.Unmarshal(data, &p) != nil {
		return false, false
	}
	if p.Virus == nil {
		return true, true
	}
	return p.Virus.Enabled, p.Virus.Action == "quarantine"
}
func (e *Engine) RealtimePolicy(workDir string) (bool, bool) {
	data, err := e.readPolicy(workDir)
	return parseRealtimePolicy(data, err)
}
func (e *Engine) readPolicy(workDir string) ([]byte, error) {
	if e.policyReader != nil {
		return e.policyReader()
	}
	return readVirusPolicy(workDir)
}
func (e *Engine) CheckRealtime(path, workDir string) *pb.VirusFinding {
	// An active scan can hold mu while policy changes. Authorize the next
	// realtime file only after its wait, including the current action choice.
	e.mu.Lock()
	defer e.mu.Unlock()
	data, err := e.readPolicy(workDir)
	enabled, quarantine := parseRealtimePolicy(data, err)
	if !enabled {
		return nil
	}
	// Whitelist and disposition belong to the same authorized snapshot. A
	// concurrent update takes effect for the next file, without mixing revisions.
	e.refreshWithPolicy(workDir, data, err)
	return e.checkFileLocked(path, workDir, quarantine)
}

// Refresh long-lived engines after signature or policy changes.
func (e *Engine) refresh(workDir string) {
	data, err := e.readPolicy(workDir)
	e.refreshWithPolicy(workDir, data, err)
}
func (e *Engine) refreshWithPolicy(workDir string, data []byte, err error) {
	db := LoadDB(workDir)
	if e.db != db {
		e.db = db
	}
	e.whitelist = parseWhitelist(data, err)
}

func (e *Engine) whitelisted(path, hash string) bool {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	for _, entry := range e.whitelist {
		if entry.Type == "hash" && hash != "" && strings.EqualFold(entry.Value, hash) {
			return true
		}
		if entry.Type != "path" || entry.Value == "" {
			continue
		}
		prefix := filepath.Clean(entry.Value)
		if runtime.GOOS == "windows" {
			prefix = strings.ToLower(prefix)
		}
		if path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, string(filepath.Separator))+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
