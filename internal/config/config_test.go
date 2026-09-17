package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMissingConfigUsesDefaults(t *testing.T) {
	got, found, err := Load(filepath.Join(t.TempDir(), DefaultPath))
	if err != nil || found || !reflect.DeepEqual(got, Defaults()) {
		t.Fatalf("config = %+v, found = %v, error = %v", got, found, err)
	}
}

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultPath)
	content := `
exclude:
  - generated
  - "fixtures/*.txt"
ignore_rules:
  - stripe-test-key
allowlist:
  - path: config/example.txt
    line: 12
    rule: aws-access-key-id
severity: MEDIUM
output: JSON
`
	writeConfig(t, path, content)
	got, found, err := Load(path)
	if err != nil || !found {
		t.Fatalf("found = %v, error = %v", found, err)
	}
	want := Config{
		Exclude:     []string{"generated", "fixtures/*.txt"},
		IgnoreRules: []string{"stripe-test-key"},
		Allowlist:   []AllowEntry{{Path: "config/example.txt", Line: 12, Rule: "aws-access-key-id"}},
		Severity:    "medium", Output: "json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config = %+v, want %+v", got, want)
	}
}

func TestInvalidConfigs(t *testing.T) {
	tests := []string{
		"unknown: true\n",
		"severity: critical\n",
		"output: xml\n",
		"ignore_rules: [same, same]\n",
		"allowlist:\n  - path: config.txt\n    line: 0\n    rule: rule\n",
		"severity: low\n---\noutput: json\n",
		"exclude: [\n",
	}
	for i, content := range tests {
		path := filepath.Join(t.TempDir(), DefaultPath)
		writeConfig(t, path, content)
		if _, _, err := Load(path); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: error = %v", i, err)
		}
	}
}

func TestConfigErrorsDoNotExposeContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultPath)
	private := "SYNTHETIC_PRIVATE_VALUE"
	writeConfig(t, path, "unknown: "+private+"\n")
	_, _, err := Load(path)
	if err == nil || strings.Contains(err.Error(), private) {
		t.Fatalf("error = %v", err)
	}
}

func TestConfigSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultPath)
	writeConfig(t, path, strings.Repeat("#", maxConfigBytes+1))
	if _, _, err := Load(path); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
