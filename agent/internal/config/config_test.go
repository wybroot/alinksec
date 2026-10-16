package config

import (
	"os"
	"strings"
	"testing"
)

func TestInvalidConfigurationErrorsDoNotEchoCredentials(t *testing.T) {
	for _, data := range []string{"unknown: TOP-SECRET\n", "enroll_token: [TOP-SECRET\n", "server_addr: TOP-SECRET\n", "server_addr: good.example:9443\n---\nenroll_token: TOP-SECRET\n"} {
		if _, err := Parse([]byte(data)); err == nil || strings.Contains(err.Error(), "TOP-SECRET") {
			t.Fatalf("invalid config accepted or error leaked value: %v", err)
		}
	}
}

func TestLoadKubernetesNodeName(t *testing.T) {
	path := t.TempDir() + "/agent.yml"
	if err := os.WriteFile(path, []byte("kubernetes_node_name: worker-a\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.KubernetesNodeName != "worker-a" {
		t.Fatalf("KubernetesNodeName = %q, want worker-a", cfg.KubernetesNodeName)
	}
}
