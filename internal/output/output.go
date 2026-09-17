// Package output produit les formats publics d'env-guard.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aaronladron/env-guard/internal/scanner"
)

var ErrWrite = errors.New("unable to write scan output")

func Human(writer io.Writer, report scanner.Report) error {
	if _, err := fmt.Fprintf(writer, "env-guard\n\n%d files scanned\n", report.FilesScanned); err != nil {
		return ErrWrite
	}
	if len(report.Findings) == 0 {
		if _, err := fmt.Fprintln(writer, "No potential secrets detected."); err != nil {
			return ErrWrite
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer, "\n%d potential secrets detected\n", len(report.Findings)); err != nil {
		return ErrWrite
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(writer, "\n%s  %s\n    %s:%d\n    Value: %s\n", finding.Severity, finding.Type, finding.File, finding.Line, finding.MaskedValue); err != nil {
			return ErrWrite
		}
	}
	return nil
}

type jsonReport struct {
	Version        int           `json:"version"`
	FilesScanned   int           `json:"files_scanned"`
	SkippedEntries int           `json:"skipped_entries"`
	Findings       []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	Type     string           `json:"type"`
	Severity scanner.Severity `json:"severity"`
	File     string           `json:"file"`
	Line     int              `json:"line"`
	Rule     string           `json:"rule"`
	Message  string           `json:"message"`
	Value    string           `json:"value"`
}

func JSON(writer io.Writer, report scanner.Report) error {
	result := jsonReport{
		Version: 1, FilesScanned: report.FilesScanned,
		SkippedEntries: report.SkippedEntries,
		Findings:       make([]jsonFinding, 0, len(report.Findings)),
	}
	for _, finding := range report.Findings {
		result.Findings = append(result.Findings, jsonFinding{
			Type: finding.Type, Severity: finding.Severity, File: finding.File,
			Line: finding.Line, Rule: finding.RuleID, Message: finding.Message,
			Value: finding.MaskedValue,
		})
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return ErrWrite
	}
	return nil
}
