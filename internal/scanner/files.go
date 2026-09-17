package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxFileBytes = 10 * 1024 * 1024

var (
	ErrInvalidOptions = errors.New("invalid scan options")
	ErrFileTooLarge   = errors.New("text file exceeds 10 MiB")
)

type AllowEntry struct {
	Path   string
	Line   int
	RuleID string
}

type Options struct {
	Exclude   []string
	Allowlist []AllowEntry
}

type Report struct {
	FilesScanned   int
	SkippedEntries int
	Findings       []Finding
}

// File représente un fichier fourni par une source autre que le disque courant,
// par exemple le contenu d'un index Git.
type File struct {
	Path    string
	Content []byte
}

func (d *Detector) validateOptions(options Options) ([]string, error) {
	patterns := []string{".git", "node_modules", "vendor", ".gitignore"}
	for _, item := range options.Exclude {
		item = strings.ReplaceAll(item, "\\", "/")
		item = strings.TrimSuffix(strings.TrimPrefix(item, "./"), "/")
		if item == "" || item == "." || strings.Contains(item, "**") || strings.Contains(item, ":") || strings.HasPrefix(item, "/") {
			return nil, ErrInvalidOptions
		}
		for _, part := range strings.Split(item, "/") {
			if part == ".." || part == "." || part == "" {
				return nil, ErrInvalidOptions
			}
		}
		if _, err := path.Match(item, ""); err != nil {
			return nil, ErrInvalidOptions
		}
		patterns = append(patterns, item)
	}
	for _, entry := range options.Allowlist {
		if !fs.ValidPath(entry.Path) || entry.Path == "." || strings.Contains(entry.Path, "\\") || entry.Line < 1 {
			return nil, ErrInvalidOptions
		}
		known := false
		for _, rule := range d.rules {
			known = known || rule.rule.ID == entry.RuleID
		}
		if !known {
			return nil, ErrInvalidOptions
		}
	}
	return patterns, nil
}

func excluded(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(pattern, "/") {
			if match, _ := path.Match(pattern, name); match {
				return true
			}
			continue
		}
		for _, part := range strings.Split(name, "/") {
			if match, _ := path.Match(pattern, part); match {
				return true
			}
		}
	}
	return false
}

// ScanFiles analyse une collection en mémoire dans l'ordre lexical des chemins.
// Le contenu reste la propriété de l'appelant et n'est jamais modifié.
func (d *Detector) ScanFiles(ctx context.Context, files []File, options Options) (Report, error) {
	if d == nil || len(d.rules) == 0 {
		return Report{}, ErrNoRules
	}
	patterns, err := d.validateOptions(options)
	if err != nil {
		return Report{}, err
	}
	ordered := append([]File(nil), files...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	report := Report{Findings: make([]Finding, 0)}
	seen := make(map[string]bool, len(ordered))
	for _, file := range ordered {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		if !fs.ValidPath(file.Path) || file.Path == "." || seen[file.Path] {
			return Report{}, ErrRead
		}
		seen[file.Path] = true
		if excluded(file.Path, patterns) {
			report.SkippedEntries++
			continue
		}
		if err := d.scanContent(ctx, &report, file.Path, file.Content, options.Allowlist); err != nil {
			return Report{}, err
		}
	}
	return report, nil
}

func allowed(f Finding, entries []AllowEntry) bool {
	for _, entry := range entries {
		if f.File == entry.Path && f.Line == entry.Line && f.RuleID == entry.RuleID {
			return true
		}
	}
	return false
}

// ScanFS parcourt les entrées dans l'ordre lexical, sans suivre les liens.
// Toute erreur invalide le rapport entier : aucun succès partiel n'est publié.
func (d *Detector) ScanFS(ctx context.Context, tree fs.FS, options Options) (Report, error) {
	if d == nil || len(d.rules) == 0 {
		return Report{}, ErrNoRules
	}
	patterns, err := d.validateOptions(options)
	if err != nil {
		return Report{}, err
	}
	if tree == nil {
		return Report{}, ErrRead
	}
	report := Report{Findings: make([]Finding, 0)}
	err = fs.WalkDir(tree, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return fmt.Errorf("%q: %w", name, ErrRead)
		}
		if name != "." && excluded(name, patterns) {
			report.SkippedEntries++
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			report.SkippedEntries++
			return nil
		}
		data, err := readFile(ctx, tree, name)
		if err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		return d.scanContent(ctx, &report, name, data, options.Allowlist)
	})
	if err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func (d *Detector) scanContent(ctx context.Context, report *Report, name string, data []byte, allowlist []AllowEntry) error {
	if binaryControl(data) || !utf8.Valid(data) {
		report.SkippedEntries++
		return nil
	}
	if len(data) > MaxFileBytes {
		return fmt.Errorf("%q: %w", name, ErrFileTooLarge)
	}
	findings, err := d.Scan(ctx, name, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%q: %w", name, err)
	}
	report.FilesScanned++
	for _, finding := range findings {
		if !allowed(finding, allowlist) {
			report.Findings = append(report.Findings, finding)
		}
	}
	return nil
}

func binaryControl(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' && b != '\f' {
			return true
		}
	}
	return false
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func readFile(ctx context.Context, tree fs.FS, name string) ([]byte, error) {
	file, err := tree.Open(name)
	if err != nil {
		return nil, ErrRead
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, ErrRead
	}
	data, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, file}, MaxFileBytes+1))
	closeErr := file.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if readErr != nil || closeErr != nil {
		return nil, ErrRead
	}
	return data, nil
}
