package scanner

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
