package scanner

import (
	"bufio"
	"context"
	"errors"
	"io"
)

// MaxLineBytes is the largest supported line, excluding its LF or CRLF ending.
// Oversized lines fail the scan instead of silently skipping potential secrets.
const MaxLineBytes = 1024 * 1024

var (
	ErrRead        = errors.New("unable to read scan input")
	ErrLineTooLong = errors.New("scan input line exceeds 1 MiB")
)

// Scan reads text without owning or closing r. Findings are ordered by line,
// then rule order, then match position within that rule. Lines are one-based.
// A failed or cancelled scan returns no partial findings. Reader errors are
// sanitized because an arbitrary reader error may contain source text.
// Cancellation is checked between reads; it cannot interrupt a blocked reader.
func (d *Detector) Scan(ctx context.Context, file string, r io.Reader) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d == nil || len(d.rules) == 0 {
		return nil, ErrNoRules
	}
	if r == nil {
		return nil, ErrRead
	}
	lines := bufio.NewScanner(r)
	// Reserve two extra bytes so a maximum-sized line can end with CRLF.
	lines.Buffer(make([]byte, 64*1024), MaxLineBytes+2)
	findings := make([]Finding, 0)
	for number := 1; ; number++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !lines.Scan() {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(lines.Bytes()) > MaxLineBytes {
			return nil, ErrLineTooLong
		}
		findings = append(findings, d.detectLine(file, number, lines.Bytes())...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := lines.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, ErrLineTooLong
		}
		return nil, ErrRead
	}
	return findings, nil
}
