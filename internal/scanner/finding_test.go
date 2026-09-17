package scanner

import "testing"

func TestParseAndFilterSeverity(t *testing.T) {
	for input, want := range map[string]Severity{"low": SeverityLow, " MEDIUM ": SeverityMedium, "HIGH": SeverityHigh} {
		got, ok := ParseSeverity(input)
		if !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v", input, got, ok)
		}
	}
	if _, ok := ParseSeverity("critical"); ok {
		t.Fatal("unsupported severity accepted")
	}
	report := Report{Findings: []Finding{
		{RuleID: "low", Severity: SeverityLow},
		{RuleID: "medium", Severity: SeverityMedium},
		{RuleID: "high", Severity: SeverityHigh},
	}}
	filtered := FilterSeverity(report, SeverityMedium)
	if len(filtered.Findings) != 2 || filtered.Findings[0].RuleID != "medium" || filtered.Findings[1].RuleID != "high" {
		t.Fatalf("findings = %+v", filtered.Findings)
	}
	if len(report.Findings) != 3 {
		t.Fatal("input report was modified")
	}
}
