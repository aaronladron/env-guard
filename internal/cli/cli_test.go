package cli

import (
	"bytes"
	"errors"
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
		{"scan help", []string{"scan", "--help"}, 0, "No files are inspected.", ""},
		{"scan short help", []string{"scan", "-h"}, 0, "Usage: env-guard scan", ""},
		{"unfinished scan fails closed", []string{"scan"}, 3, "", "no files were scanned"},
		{"unknown command", []string{"unknown"}, 2, "", "unsupported command"},
		{"unknown flag", []string{"--unknown"}, 2, "", "unsupported command"},
		{"staged is not supported yet", []string{"scan", "--staged"}, 2, "", "unsupported command"},
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
