// Package scanner detects potential secrets in text streams using supplied rules.
// Filesystem traversal is provided separately by ScanFS; no network is used.
package scanner

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

var (
	ErrNoRules     = errors.New("no detection rules configured")
	ErrInvalidRule = errors.New("invalid detection rule")
)

// Rule describes a line-based detection pattern. SecretGroup selects the regexp
// capture containing the secret; zero selects the entire match. Metadata must be
// static descriptions, never source text or credentials.
type Rule struct {
	ID          string
	Type        string
	Severity    Severity
	Message     string
	Pattern     string
	SecretGroup int
	// Generic active le filtrage contextuel des affectations non spécifiques.
	Generic    bool
	MinEntropy float64
}

type compiledRule struct {
	rule    Rule
	pattern *regexp.Regexp
}

// Detector holds validated rules. It is immutable and safe for concurrent scans
// provided that each scan has its own reader.
type Detector struct {
	rules []compiledRule
}

// NewDetector validates and compiles all rules before any input is read.
func NewDetector(rules []Rule) (*Detector, error) {
	if len(rules) == 0 {
		return nil, ErrNoRules
	}
	d := &Detector{rules: make([]compiledRule, 0, len(rules))}
	ids := make(map[string]bool, len(rules))
	for i, rule := range rules {
		invalid := func(reason string) (*Detector, error) {
			// Do not echo rule content: a malformed pattern could contain a secret.
			return nil, fmt.Errorf("%w at index %d: %s", ErrInvalidRule, i, reason)
		}
		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Type) == "" || strings.TrimSpace(rule.Message) == "" {
			return invalid("ID, type and message are required")
		}
		if ids[rule.ID] {
			return invalid("duplicate ID")
		}
		switch rule.Severity {
		case SeverityLow, SeverityMedium, SeverityHigh:
		default:
			return invalid("unsupported severity")
		}
		if math.IsNaN(rule.MinEntropy) || math.IsInf(rule.MinEntropy, 0) || rule.MinEntropy < 0 || rule.MinEntropy > 8 || (!rule.Generic && rule.MinEntropy != 0) {
			return invalid("invalid entropy threshold")
		}
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return invalid("malformed pattern")
		}
		if pattern.MatchString("") {
			return invalid("pattern matches empty input")
		}
		if rule.SecretGroup < 0 || rule.SecretGroup > pattern.NumSubexp() {
			return invalid("secret capture group is out of range")
		}
		ids[rule.ID] = true
		d.rules = append(d.rules, compiledRule{rule: rule, pattern: pattern})
	}
	return d, nil
}

func (d *Detector) detectLine(file string, number int, line []byte) []Finding {
	var findings []Finding
	for _, compiled := range d.rules {
		rule := compiled.rule
		for _, match := range compiled.pattern.FindAllSubmatchIndex(line, -1) {
			start, end := match[2*rule.SecretGroup], match[2*rule.SecretGroup+1]
			// Optional captures can be absent; empty captures are not secrets.
			if start < 0 || end <= start {
				continue
			}
			if rule.Generic && !d.keepGeneric(file, line[start:end], rule) {
				continue
			}
			findings = append(findings, Finding{
				Type:        rule.Type,
				Severity:    rule.Severity,
				File:        file,
				Line:        number,
				RuleID:      rule.ID,
				Message:     rule.Message,
				MaskedValue: "[REDACTED]",
			})
		}
	}
	return findings
}
