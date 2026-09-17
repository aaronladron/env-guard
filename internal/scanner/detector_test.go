package scanner

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// These deliberately synthetic values do not follow any provider's key format.
func syntheticRule() Rule {
	return Rule{
		ID: "synthetic-secret", Type: "Synthetic secret", Severity: SeverityHigh,
		Message: "Synthetic secret detected", Pattern: `secret=(SYNTHETIC_[A-Z]+)`, SecretGroup: 1,
	}
}

func testDetector(t *testing.T, rules ...Rule) *Detector {
	t.Helper()
	if len(rules) == 0 {
		rules = []Rule{syntheticRule()}
	}
	d, err := NewDetector(rules)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRuleValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Rule)
	}{
		{"missing ID", func(r *Rule) { r.ID = "  " }},
		{"missing type", func(r *Rule) { r.Type = "" }},
		{"missing message", func(r *Rule) { r.Message = "" }},
		{"unknown severity", func(r *Rule) { r.Severity = "CRITICAL" }},
		{"invalid regexp", func(r *Rule) { r.Pattern = "[SYNTHETIC_PRIVATE" }},
		{"empty regexp", func(r *Rule) { r.Pattern = "" }},
		{"empty match", func(r *Rule) { r.Pattern = "a*" }},
		{"negative group", func(r *Rule) { r.SecretGroup = -1 }},
		{"missing capture", func(r *Rule) { r.SecretGroup = 2 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := syntheticRule()
			tt.edit(&rule)
			d, err := NewDetector([]Rule{rule})
			if d != nil || !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("NewDetector = %v, %v; want nil, ErrInvalidRule", d, err)
			}
			if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE") {
				t.Fatal("pattern leaked in validation error")
			}
		})
	}
	if d, err := NewDetector(nil); d != nil || !errors.Is(err, ErrNoRules) {
		t.Fatalf("empty rules = %v, %v", d, err)
	}
	if d, err := NewDetector([]Rule{syntheticRule(), syntheticRule()}); d != nil || !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("duplicate rules = %v, %v", d, err)
	}
	for _, severity := range []Severity{SeverityLow, SeverityMedium, SeverityHigh} {
		rule := syntheticRule()
		rule.Severity = severity
		testDetector(t, rule)
	}
}

func TestFindingsAreLocatedAndRedacted(t *testing.T) {
	d := testDetector(t)
	input := "name=example\r\n\r\nsecret=SYNTHETIC_ALPHA secret=SYNTHETIC_BETA\r\nsecret=SYNTHETIC_GAMMA"
	got, err := d.Scan(context.Background(), "config/example.conf", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	var want []Finding
	for _, line := range []int{3, 3, 4} {
		want = append(want, Finding{
			Type: "Synthetic secret", Severity: SeverityHigh, File: "config/example.conf",
			Line: line, RuleID: "synthetic-secret", Message: "Synthetic secret detected", MaskedValue: "[REDACTED]",
		})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings = %#v, want %#v", got, want)
	}
	for _, value := range []string{"SYNTHETIC_ALPHA", "SYNTHETIC_BETA", "SYNTHETIC_GAMMA"} {
		if strings.Contains(fmt.Sprintf("%+v %#v", got, got), value) {
			t.Fatal("source text leaked into findings")
		}
	}
}

func TestCaptureGroups(t *testing.T) {
	tests := []struct {
		name, pattern, input string
		group, count         int
	}{
		{"entire match", `SYNTHETIC_VALUE`, "SYNTHETIC_VALUE", 0, 1},
		{"selected capture", `(secret)=(SYNTHETIC_VALUE)`, "secret=SYNTHETIC_VALUE", 2, 1},
		{"missing optional capture", `secret(?:=(SYNTHETIC_VALUE))?`, "secret", 1, 0},
		{"empty capture", `secret=([A-Z]*)`, "secret=", 1, 0},
		{"zero width match", `\b`, "word", 0, 0},
		{"short value", `secret=(x)`, "secret=x", 1, 1},
		{"unicode value", `secret=(秘密)`, "secret=秘密", 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := syntheticRule()
			rule.Pattern, rule.SecretGroup = tt.pattern, tt.group
			got, err := testDetector(t, rule).Scan(context.Background(), "fixture", strings.NewReader(tt.input))
			if err != nil || len(got) != tt.count {
				t.Fatalf("got %d findings, %v; want %d", len(got), err, tt.count)
			}
			for _, finding := range got {
				if finding.MaskedValue != "[REDACTED]" {
					t.Fatalf("unexpected redaction: %q", finding.MaskedValue)
				}
			}
		})
	}
}

func TestRuleOrderAndOwnership(t *testing.T) {
	first, second := syntheticRule(), syntheticRule()
	first.ID, second.ID = "first", "second"
	second.Severity = SeverityMedium
	rules := []Rule{first, second}
	d := testDetector(t, rules...)
	rules[0].ID = "changed"
	rules[0].Pattern = "invalid["
	got, err := d.Scan(context.Background(), "fixture", strings.NewReader("secret=SYNTHETIC_VALUE\nsecret=SYNTHETIC_VALUE"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.RuleID)
	}
	if !reflect.DeepEqual(ids, []string{"first", "second", "first", "second"}) {
		t.Fatalf("unexpected rule order or mutated rules: %v", ids)
	}
	if got[1].Severity != SeverityMedium {
		t.Fatalf("severity = %s, want MEDIUM", got[1].Severity)
	}
}

func TestConcurrentScans(t *testing.T) {
	d := testDetector(t)
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := d.Scan(context.Background(), "fixture", strings.NewReader("secret=SYNTHETIC_VALUE"))
			if err != nil || len(got) != 1 {
				t.Errorf("concurrent scan: %d findings, %v", len(got), err)
			}
		}()
	}
	group.Wait()
}
