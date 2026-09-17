package cli

import (
	"bytes"
	"errors"
	"os"
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
		{"unknown command", []string{"unknown"}, 2, "", "unsupported command"},
		{"unknown flag", []string{"--unknown"}, 2, "", "unsupported command"},
		{"staged is not supported yet", []string{"scan", "--staged"}, 2, "", "unsupported command"},
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
