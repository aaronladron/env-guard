package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		out  string
		err  string
	}{
		{"no arguments", nil, 0, "Usage:", ""},
		{"help", []string{"--help"}, 0, "env-guard scan", ""},
		{"short help", []string{"-h"}, 0, "Usage:", ""},
		{"help command", []string{"help"}, 0, "Usage:", ""},
		{"scan help", []string{"scan", "--help"}, 0, "--exclude", ""},
		{"scan short help", []string{"scan", "-h"}, 0, "Usage: env-guard scan", ""},
		{"init help", []string{"init", "--help"}, 0, "--wrap", ""},
		{"conflicting init options", []string{"init", "--wrap", "--remove"}, 2, "", "unsupported command"},
		{"unknown command", []string{"unknown"}, 2, "", "unsupported command"},
		{"unknown flag", []string{"--unknown"}, 2, "", "unsupported command"},
		{"duplicate staged option", []string{"scan", "--staged", "--staged"}, 2, "", "unsupported command"},
		{"duplicate JSON option", []string{"scan", "--json", "--json"}, 2, "", "unsupported command"},
		{"missing exclusion", []string{"scan", "--exclude"}, 2, "", "unsupported command"},
		{"invalid exclusion", []string{"scan", "--exclude", "../outside"}, 2, "", "unsupported command"},
		{"unexpected path", []string{"scan", "some-path"}, 2, "", "unsupported command"},
		{"extra help arguments", []string{"--help", "extra"}, 2, "", "unsupported command"},
		{"extra scan help arguments", []string{"scan", "--help", "extra"}, 2, "", "unsupported command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tt.args, &stdout, &stderr); code != tt.code {
				t.Fatalf("exit code = %d, want %d", code, tt.code)
			}
			for _, stream := range []struct{ name, got, want string }{
				{"stdout", stdout.String(), tt.out}, {"stderr", stderr.String(), tt.err},
			} {
				if (stream.want == "" && stream.got != "") || !strings.Contains(stream.got, stream.want) {
					t.Errorf("%s = %q, want %q", stream.name, stream.got, stream.want)
				}
			}
		})
	}
}

func TestJSONAndConfiguration(t *testing.T) {
	t.Run("JSON flag", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile("config.txt", []byte("port=8080\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan", "--json"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		var result struct {
			Version  int   `json:"version"`
			Findings []any `json:"findings"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Version != 1 || result.Findings == nil {
			t.Fatalf("JSON = %q, error = %v", stdout.String(), err)
		}
	})

	t.Run("ignored rule and JSON output from config", func(t *testing.T) {
		t.Chdir(t.TempDir())
		value := "AKIA" + strings.Repeat("A", 16)
		if err := os.WriteFile("config.txt", []byte("key="+value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		content := "ignore_rules:\n  - aws-access-key-id\noutput: json\n"
		if err := os.WriteFile(".env-guard.yaml", []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		if strings.Contains(stdout.String(), value) || !strings.Contains(stdout.String(), `"findings": []`) {
			t.Fatalf("output = %q", stdout.String())
		}
	})

	t.Run("severity threshold", func(t *testing.T) {
		t.Chdir(t.TempDir())
		value := "sk_test_" + strings.Repeat("a", 24)
		if err := os.WriteFile("config.txt", []byte("key="+value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(".env-guard.yaml", []byte("severity: high\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan"}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "No potential secrets") {
			t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
		}
	})

	t.Run("allowlist", func(t *testing.T) {
		t.Chdir(t.TempDir())
		value := "AKIA" + strings.Repeat("A", 16)
		if err := os.WriteFile("config.txt", []byte("key="+value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		content := "allowlist:\n  - path: config.txt\n    line: 1\n    rule: aws-access-key-id\n"
		if err := os.WriteFile(".env-guard.yaml", []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
	})

	t.Run("configuration exclusions", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.Mkdir("generated", 0o700); err != nil {
			t.Fatal(err)
		}
		value := "AKIA" + strings.Repeat("A", 16)
		if err := os.WriteFile(filepath.Join("generated", "config.txt"), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(".env-guard.yaml", []byte("exclude: [generated]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
	})

	t.Run("unknown rule is rejected", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile(".env-guard.yaml", []byte("ignore_rules: [unknown]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan"}, &stdout, &stderr); code != ExitInternal || !strings.Contains(stderr.String(), "invalid .env-guard.yaml") {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
	})
}

func TestInitCommand(t *testing.T) {
	executable, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}

	t.Run("install is idempotent and removable", func(t *testing.T) {
		directory := initRepository(t, executable)
		t.Chdir(directory)
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"init"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		path := filepath.Join(directory, ".git", "hooks", "pre-commit")
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), "env-guard scan --staged") {
			t.Fatalf("hook = %q, error = %v", data, err)
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run([]string{"init"}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "already installed") {
			t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run([]string{"init", "--remove"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("hook still exists: %v", err)
		}
	})

	t.Run("existing hook requires wrap and is restored", func(t *testing.T) {
		directory := initRepository(t, executable)
		t.Chdir(directory)
		path := filepath.Join(directory, ".git", "hooks", "pre-commit")
		original := "#!/bin/sh\necho existing\n"
		if err := os.WriteFile(path, []byte(original), 0o755); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"init"}, &stdout, &stderr); code != ExitUsage || !strings.Contains(stderr.String(), "--wrap") {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		data, _ := os.ReadFile(path)
		if string(data) != original {
			t.Fatal("existing hook changed after refused install")
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run([]string{"init", "--wrap"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run([]string{"init", "--remove"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		data, err = os.ReadFile(path)
		if err != nil || string(data) != original {
			t.Fatalf("restored hook = %q, error = %v", data, err)
		}
	})
}

func initRepository(t *testing.T, executable string) string {
	t.Helper()
	directory := t.TempDir()
	command := exec.Command(executable, "init", "--quiet")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	return directory
}

func TestScanCommand(t *testing.T) {
	t.Run("clean project", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile("config.txt", []byte("port=8080\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "1 files scanned") || !strings.Contains(stdout.String(), "No potential secrets") {
			t.Fatalf("unexpected output: %q", stdout.String())
		}
	})

	t.Run("finding", func(t *testing.T) {
		t.Chdir(t.TempDir())
		value := "AKIA" + strings.Repeat("A", 16)
		if err := os.WriteFile("config.txt", []byte("key="+value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan"}, &stdout, &stderr); code != ExitFindings {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		if strings.Contains(stdout.String(), value) || !strings.Contains(stdout.String(), "[REDACTED]") || !strings.Contains(stdout.String(), "config.txt:1") {
			t.Fatalf("unexpected output: %q", stdout.String())
		}
	})

	t.Run("repeated exclusions", func(t *testing.T) {
		t.Chdir(t.TempDir())
		for _, name := range []string{"one.txt", "two.txt", "keep.txt"} {
			if err := os.WriteFile(name, []byte("port=8080\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		var stdout, stderr bytes.Buffer
		code := Run([]string{"scan", "--exclude", "one.txt", "--exclude=two.txt"}, &stdout, &stderr)
		if code != ExitOK || !strings.Contains(stdout.String(), "1 files scanned") {
			t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
		}
	})

	t.Run("staged content", func(t *testing.T) {
		executable, err := exec.LookPath("git")
		if err != nil {
			t.Skip("git is not installed")
		}
		directory := t.TempDir()
		t.Chdir(directory)
		command := exec.Command(executable, "init", "--quiet")
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git init: %v: %s", err, output)
		}
		value := "AKIA" + strings.Repeat("A", 16)
		path := filepath.Join(directory, "config.txt")
		if err := os.WriteFile(path, []byte("key="+value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		command = exec.Command(executable, "add", "config.txt")
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git add: %v: %s", err, output)
		}
		if err := os.WriteFile(path, []byte("working tree is clean\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan", "--staged"}, &stdout, &stderr); code != ExitFindings {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
		if strings.Contains(stdout.String(), value) || !strings.Contains(stdout.String(), "config.txt:1") {
			t.Fatalf("unexpected output: %q", stdout.String())
		}
	})

	t.Run("git executable missing", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("PATH", t.TempDir())
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"scan", "--staged"}, &stdout, &stderr); code != ExitInternal {
			t.Fatalf("exit code = %d", code)
		}
		if stderr.String() != "Error: Git executable not found\n" || stdout.Len() != 0 {
			t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
		}
	})
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	if code := Run([]string{"--help"}, failingWriter{}, &stderr); code != ExitInternal {
		t.Fatalf("exit code = %d, want %d", code, ExitInternal)
	}
	if !strings.Contains(stderr.String(), "unable to write output") {
		t.Fatalf("missing output error: %q", stderr.String())
	}
}

func TestInvalidArgumentIsNotEchoed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	argument := "sensitive-value-passed-by-mistake"
	Run([]string{argument}, &stdout, &stderr)
	if strings.Contains(stdout.String()+stderr.String(), argument) {
		t.Fatal("argument leaked in output")
	}
}
