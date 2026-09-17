package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aaronladron/env-guard/internal/scanner"
)

func sampleReport() scanner.Report {
	return scanner.Report{
		FilesScanned: 2, SkippedEntries: 1,
		Findings: []scanner.Finding{{
			Type: "Synthetic", Severity: scanner.SeverityHigh, File: "config.txt",
			Line: 4, RuleID: "synthetic", Message: "Synthetic finding", MaskedValue: "[REDACTED]",
		}},
	}
}

func TestHumanOutput(t *testing.T) {
	var output bytes.Buffer
	if err := Human(&output, sampleReport()); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{"2 files scanned", "1 potential secrets detected", "config.txt:4", "[REDACTED]"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain %q: %q", want, got)
		}
	}
}

func TestJSONOutputIsStableAndRedacted(t *testing.T) {
	var output bytes.Buffer
	if err := JSON(&output, sampleReport()); err != nil {
		t.Fatal(err)
	}
	want := `{
  "version": 1,
  "files_scanned": 2,
  "skipped_entries": 1,
  "findings": [
    {
      "type": "Synthetic",
      "severity": "HIGH",
      "file": "config.txt",
      "line": 4,
      "rule": "synthetic",
      "message": "Synthetic finding",
      "value": "[REDACTED]"
    }
  ]
}
`
	if output.String() != want {
		t.Fatalf("JSON = %q, want %q", output.String(), want)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyJSONFindingsIsArray(t *testing.T) {
	var output bytes.Buffer
	if err := JSON(&output, scanner.Report{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"findings": []`) {
		t.Fatalf("JSON = %q", output.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("private writer failure") }

func TestOutputErrorsAreSanitized(t *testing.T) {
	for _, render := range []func(writer interface{ Write([]byte) (int, error) }, report scanner.Report) error{
		func(writer interface{ Write([]byte) (int, error) }, report scanner.Report) error {
			return Human(writer, report)
		},
		func(writer interface{ Write([]byte) (int, error) }, report scanner.Report) error {
			return JSON(writer, report)
		},
	} {
		err := render(failingWriter{}, sampleReport())
		if !errors.Is(err, ErrWrite) || strings.Contains(err.Error(), "private") {
			t.Fatalf("error = %v", err)
		}
	}
}
