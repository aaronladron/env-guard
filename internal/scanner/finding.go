package scanner

import "strings"

// Severity is the impact assigned to a detection rule.
type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Finding contains rule metadata and a location, never the matched source text.
// Rule metadata and file names are supplied by the caller and are not redacted.
type Finding struct {
	Type        string
	Severity    Severity
	File        string
	Line        int
	RuleID      string
	Message     string
	MaskedValue string
}

func ParseSeverity(value string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return SeverityLow, true
	case "medium":
		return SeverityMedium, true
	case "high":
		return SeverityHigh, true
	default:
		return "", false
	}
}

func FilterSeverity(report Report, minimum Severity) Report {
	minimumRank := severityRank(minimum)
	filtered := report
	filtered.Findings = make([]Finding, 0, len(report.Findings))
	for _, finding := range report.Findings {
		if severityRank(finding.Severity) >= minimumRank {
			filtered.Findings = append(filtered.Findings, finding)
		}
	}
	return filtered
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
