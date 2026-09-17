package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestGenericRules(t *testing.T) {
	d := testDetector(t, DefaultRules()...)
	tests := []struct {
		name, file, input, rule string
		want                    int
	}{
		{"token with context", "config.env", "API_TOKEN=azBY09_qpLM27-xR", "generic-token", 1},
		{"password with context", "config.yaml", `password: "correct-horse-7"`, "config-password", 1},
		{"placeholder", "config.env", "API_TOKEN=YOUR_API_KEY_HERE", "", 0},
		{"environment reference", "config.js", "token=process.env.API_TOKEN", "", 0},
		{"low entropy", "config.env", "token=aaaaaaaaaaaaaaaa", "", 0},
		{"documentation", "docs/setup.md", "token=azBY09_qpLM27-xR", "", 0},
		{"missing context", "config.env", "azBY09_qpLM27-xR", "", 0},
		{"provider rule wins", "config.env", "token=AKIA" + strings.Repeat("A", 16), "aws-access-key-id", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Scan(context.Background(), tt.file, strings.NewReader(tt.input))
			if err != nil || len(got) != tt.want {
				t.Fatalf("got %d findings, %v; want %d", len(got), err, tt.want)
			}
			if tt.want == 1 && got[0].RuleID != tt.rule {
				t.Fatalf("rule = %q, want %q", got[0].RuleID, tt.rule)
			}
		})
	}
}

func TestEntropyValidation(t *testing.T) {
	for _, threshold := range []float64{-1, 9} {
		rule := syntheticRule()
		rule.Generic = true
		rule.MinEntropy = threshold
		if _, err := NewDetector([]Rule{rule}); err == nil {
			t.Fatalf("threshold %v accepted", threshold)
		}
	}
	rule := syntheticRule()
	rule.MinEntropy = 1
	if _, err := NewDetector([]Rule{rule}); err == nil {
		t.Fatal("entropy threshold accepted on a specific rule")
	}
}
