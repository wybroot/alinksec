package virusscan

import (
	"encoding/json"
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
	data, err := os.ReadFile(filepath.Join(workDir, "policy.json"))
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

// Refresh long-lived engines after signature or policy changes, before consulting clean caches.
func (e *Engine) refresh(workDir string) {
	db := LoadDB(workDir)
	if e.db != db {
		e.db = db
		e.cache = map[string]cacheEntry{}
	}
	e.whitelist = loadWhitelist(workDir)
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
