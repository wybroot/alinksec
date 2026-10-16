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
	if e.policyReader != nil {
		data, err := e.policyReader()
		return parseRealtimePolicy(data, err)
	}
	return RealtimePolicy(workDir)
}
func (e *Engine) CheckRealtime(path, workDir string) *pb.VirusFinding {
	enabled, quarantine := e.RealtimePolicy(workDir)
	if !enabled {
		return nil
	}
	return e.CheckFile(path, workDir, quarantine)
}

// Refresh long-lived engines after signature or policy changes, before consulting clean caches.
func (e *Engine) refresh(workDir string) {
	db := LoadDB(workDir)
	if e.db != db {
		e.db = db
	}
	if e.policyReader != nil {
		data, err := e.policyReader()
		e.whitelist = parseWhitelist(data, err)
	} else {
		e.whitelist = loadWhitelist(workDir)
	}
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
