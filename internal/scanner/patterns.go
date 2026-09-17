package scanner

// DefaultRules renvoie une copie du catalogue, modifiable par l'appelant.
// Les longueurs servent à repérer des formats plausibles, pas à valider une clé.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID: "aws-access-key-id", Type: "AWS access key ID", Severity: SeverityHigh,
			Message: "Potential AWS access key ID detected",
			Pattern: `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`,
		},
		{
			ID: "github-classic-token", Type: "GitHub token", Severity: SeverityHigh,
			Message: "Potential GitHub token detected",
			Pattern: `\bgh[pou]_[A-Za-z0-9]{36}\b`,
		},
		{
			ID: "stripe-live-key", Type: "Stripe live key", Severity: SeverityHigh,
			Message: "Potential Stripe live secret or restricted key detected",
			Pattern: `\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b`,
		},
		{
			ID: "stripe-test-key", Type: "Stripe test key", Severity: SeverityMedium,
			Message: "Potential Stripe test secret or restricted key detected",
			Pattern: `\b(?:sk|rk)_test_[A-Za-z0-9]{24,}\b`,
		},
		{
			ID: "private-key-header", Type: "Private key", Severity: SeverityHigh,
			Message: "Potential private key header detected",
			Pattern: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`,
		},
		{
			ID: "generic-token", Type: "Generic API key or token", Severity: SeverityMedium,
			Message:     "Potential hardcoded API key, token or secret detected",
			Pattern:     `(?i)\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|credentials?)\b["']?\s*(?::=|=|:)\s*["']?([^\s"'#;,}\]]{12,})`,
			SecretGroup: 1, Generic: true, MinEntropy: 3,
		},
		{
			ID: "config-password", Type: "Hardcoded password", Severity: SeverityMedium,
			Message:     "Potential hardcoded password detected",
			Pattern:     `(?i)\b(?:[a-z0-9]+[_-])*(?:password|passwd|pwd)\b["']?\s*(?::=|=|:)\s*((?:"[^"\r\n]{4,}")|(?:'[^'\r\n]{4,}')|(?:[^\s"'#;,}\]]{4,}))`,
			SecretGroup: 1, Generic: true,
		},
	}
}
