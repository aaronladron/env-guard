package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultRulesDetectSupportedFormats(t *testing.T) {
	d := testDetector(t, DefaultRules()...)
	type detectionCase struct {
		name, value, id string
		severity        Severity
	}
	tests := []detectionCase{
		{"AWS permanent", "AKIA" + strings.Repeat("A", 16), "aws-access-key-id", SeverityHigh},
		{"AWS temporary", "ASIA" + strings.Repeat("2", 16), "aws-access-key-id", SeverityHigh},
	}
	for _, prefix := range []string{"ghp_", "gho_", "ghu_"} {
		tests = append(tests, detectionCase{prefix, prefix + strings.Repeat("aB0", 12), "github-classic-token", SeverityHigh})
	}
	for _, prefix := range []string{"sk", "rk"} {
		for _, size := range []int{24, 99, 256} {
			for _, mode := range []string{"live", "test"} {
				severity := SeverityHigh
				if mode == "test" {
					severity = SeverityMedium
				}
				tests = append(tests, detectionCase{fmt.Sprintf("Stripe %s %s %d", prefix, mode, size), prefix + "_" + mode + "_" + strings.Repeat("a", size), "stripe-" + mode + "-key", severity})
			}
		}
	}
	for _, kind := range []string{"", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "} {
		tests = append(tests, detectionCase{kind + "private key", "-----BEGIN " + kind + "PRIVATE KEY-----", "private-key-header", SeverityHigh})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, input := range []string{tt.value, `value="` + tt.value + `"`, "\n" + tt.value + "\n"} {
				got, err := d.Scan(context.Background(), "fixture", strings.NewReader(input))
				if err != nil || len(got) != 1 {
					t.Fatalf("got %d findings, %v; want one", len(got), err)
				}
				f := got[0]
				if f.RuleID != tt.id || f.Severity != tt.severity || f.MaskedValue != "[REDACTED]" {
					t.Fatalf("unexpected finding: %+v", f)
				}
				if strings.Contains(fmt.Sprintf("%#v", got), tt.value) {
					t.Fatal("matched value leaked")
				}
			}
		})
	}
}

func TestDefaultRulesRejectNearMatches(t *testing.T) {
	aws := "AKIA" + strings.Repeat("A", 16)
	github := "ghp_" + strings.Repeat("a", 36)
	stripe := "sk_live_" + strings.Repeat("a", 24)
	inputs := []string{
		"AKIA" + strings.Repeat("A", 15), aws + "A", strings.ToLower(aws),
		"ghp_" + strings.Repeat("a", 35), github + "a", strings.ToUpper(github),
		"sk_live_" + strings.Repeat("a", 23), "pk_live_" + strings.Repeat("a", 24),
		"pk_test_" + strings.Repeat("a", 24),
		"-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----",
		"-----END PRIVATE KEY-----", "-----BEGIN UNKNOWN PRIVATE KEY-----",
		"YOUR_API_KEY_HERE", "your-api-key", "example-api-key", "test-token", "xxxxxxxx", "changeme",
	}
	for _, value := range []string{aws, github, stripe} {
		inputs = append(inputs, "word"+value, "_"+value, value+"_suffix")
	}
	d := testDetector(t, DefaultRules()...)
	for i, input := range inputs {
		got, err := d.Scan(context.Background(), "fixture", strings.NewReader(input))
		if err != nil || len(got) != 0 {
			t.Errorf("case %d: got %d findings, %v; want none", i, len(got), err)
		}
	}
}

func TestAdjacentTokensAreBothDetected(t *testing.T) {
	d := testDetector(t, DefaultRules()...)
	for _, value := range []string{"AKIA" + strings.Repeat("A", 16), "ghp_" + strings.Repeat("a", 36), "sk_live_" + strings.Repeat("a", 24)} {
		for _, separator := range []string{" ", ",", ";"} {
			got, err := d.Scan(context.Background(), "fixture", strings.NewReader(value+separator+value))
			if err != nil || len(got) != 2 {
				t.Fatalf("separator %q: got %d findings, %v; want two", separator, len(got), err)
			}
		}
	}
}

func TestDefaultRulesReturnsIndependentCatalogs(t *testing.T) {
	first := DefaultRules()
	first[0].ID = "changed"
	first[0].Pattern = "["
	second := DefaultRules()
	if second[0].ID != "aws-access-key-id" {
		t.Fatal("catalog changed through caller-owned slice")
	}
	testDetector(t, second...)
}

func TestDefaultRulesFixtures(t *testing.T) {
	replace := strings.NewReplacer(
		"{{AWS_ACCESS_KEY}}", "AKIA"+strings.Repeat("A", 16),
		"{{GITHUB_TOKEN}}", "ghp_"+strings.Repeat("a", 36),
		"{{STRIPE_LIVE_KEY}}", "sk_live_"+strings.Repeat("a", 24),
		"{{STRIPE_TEST_KEY}}", "rk_test_"+strings.Repeat("a", 24),
	)
	type expected struct {
		id   string
		line int
	}
	tests := []struct {
		file string
		want []expected
	}{
		{"aws-key.txt", []expected{{"aws-access-key-id", 3}}},
		{"github-token.txt", []expected{{"github-classic-token", 3}}},
		{"stripe-key.txt", []expected{{"stripe-live-key", 2}, {"stripe-test-key", 3}}},
		{"private-key.pem", []expected{{"private-key-header", 1}}},
		{"fake-secret.txt", nil},
		{"documentation.md", nil},
		{"normal-config.json", nil},
	}
	d := testDetector(t, DefaultRules()...)
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got, err := d.Scan(context.Background(), tt.file, strings.NewReader(replace.Replace(string(data))))
			if err != nil || len(got) != len(tt.want) {
				t.Fatalf("got %d findings, %v; want %d", len(got), err, len(tt.want))
			}
			for i, want := range tt.want {
				if got[i].File != tt.file || got[i].Line != want.line || got[i].RuleID != want.id {
					t.Errorf("finding %d: %+v, want %+v", i, got[i], want)
				}
			}
		})
	}
}
