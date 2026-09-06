package config

import "testing"

func TestWriteExamplePersistsEnrollmentCA(t *testing.T) {
	path := t.TempDir() + "/agent.yml"
	if err := WriteExample(path, "server.example:9443", "ENROLL-TEST", "/etc/alinksec/ca.crt"); err != nil {
		t.Fatalf("WriteExample() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.EnrollCAFile != "/etc/alinksec/ca.crt" {
		t.Fatalf("EnrollCAFile = %q, want configured CA path", cfg.EnrollCAFile)
	}
	if err := ClearEnrollToken(path); err != nil {
		t.Fatalf("ClearEnrollToken() error = %v", err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load() after ClearEnrollToken() error = %v", err)
	}
	if cfg.EnrollToken != "" {
		t.Fatalf("EnrollToken = %q, want empty", cfg.EnrollToken)
	}
}
