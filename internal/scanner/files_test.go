package scanner

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestScanFS(t *testing.T) {
	key := "AKIA" + strings.Repeat("A", 16)
	tree := fstest.MapFS{
		"app/config.txt":               {Data: []byte("region=eu\nkey=" + key)},
		"app/clean.txt":                {Data: []byte("port=8080\n")},
		"app/image.bin":                {Data: []byte("prefix\x00" + key)},
		"app/invalid.txt":              {Data: []byte{0xff, 0xfe, 0xfd}},
		".git/objects/data":            {Data: []byte(key)},
		"node_modules/pkg/index.js":    {Data: []byte(key)},
		"vendor/example/config.txt":    {Data: []byte(key)},
		"nested/.gitignore":            {Data: []byte(key)},
		"generated/ignored-config.txt": {Data: []byte(key)},
	}
	d := testDetector(t, DefaultRules()...)
	report, err := d.ScanFS(context.Background(), tree, Options{Exclude: []string{"generated"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 2 || len(report.Findings) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Findings[0].File != "app/config.txt" || report.Findings[0].Line != 2 {
		t.Fatalf("unexpected finding: %+v", report.Findings[0])
	}
}

func TestScanFSExclusionPatterns(t *testing.T) {
	key := "AKIA" + strings.Repeat("A", 16)
	tree := fstest.MapFS{
		"build/keep.txt":   {Data: []byte(key)},
		"build/ignore.log": {Data: []byte(key)},
		"other/ignore.log": {Data: []byte(key)},
	}
	d := testDetector(t, DefaultRules()...)
	report, err := d.ScanFS(context.Background(), tree, Options{Exclude: []string{"build/*.log"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}
}

func TestScanFSAllowlistIsExact(t *testing.T) {
	key := "AKIA" + strings.Repeat("A", 16)
	tree := fstest.MapFS{"config.txt": {Data: []byte(key + "\n" + key)}}
	d := testDetector(t, DefaultRules()...)
	report, err := d.ScanFS(context.Background(), tree, Options{Allowlist: []AllowEntry{{
		Path: "config.txt", Line: 1, RuleID: "aws-access-key-id",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Line != 2 {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
}

func TestScanFSRejectsInvalidOptions(t *testing.T) {
	d := testDetector(t, DefaultRules()...)
	tests := []Options{
		{Exclude: []string{"../outside"}},
		{Exclude: []string{"[invalid"}},
		{Exclude: []string{"**/*.txt"}},
		{Allowlist: []AllowEntry{{Path: "../outside", Line: 1, RuleID: "aws-access-key-id"}}},
		{Allowlist: []AllowEntry{{Path: "config.txt", Line: 0, RuleID: "aws-access-key-id"}}},
		{Allowlist: []AllowEntry{{Path: "config.txt", Line: 1, RuleID: "unknown"}}},
	}
	for i, options := range tests {
		if _, err := d.ScanFS(context.Background(), fstest.MapFS{}, options); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("case %d: error = %v", i, err)
		}
	}
}

func TestScanFSFailuresReturnNoReport(t *testing.T) {
	d := testDetector(t, DefaultRules()...)
	t.Run("oversized text", func(t *testing.T) {
		tree := fstest.MapFS{"large.txt": {Data: []byte(strings.Repeat("a", MaxFileBytes+1))}}
		report, err := d.ScanFS(context.Background(), tree, Options{})
		if !errors.Is(err, ErrFileTooLarge) || report.FilesScanned != 0 || report.SkippedEntries != 0 || report.Findings != nil {
			t.Fatalf("report = %+v, error = %v", report, err)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report, err := d.ScanFS(ctx, fstest.MapFS{"file.txt": {Data: []byte("clean")}}, Options{})
		if !errors.Is(err, context.Canceled) || report.FilesScanned != 0 || report.SkippedEntries != 0 || report.Findings != nil {
			t.Fatalf("report = %+v, error = %v", report, err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		tree := fstest.MapFS{"denied.txt": {Mode: fs.ModeIrregular}}
		report, err := d.ScanFS(context.Background(), tree, Options{})
		if err != nil || report.SkippedEntries != 1 {
			t.Fatalf("report = %+v, error = %v", report, err)
		}
	})
}

func TestScanFilesOrdersAndFiltersSources(t *testing.T) {
	key := "AKIA" + strings.Repeat("A", 16)
	files := []File{
		{Path: "z.txt", Content: []byte(key)},
		{Path: "node_modules/pkg/a.txt", Content: []byte(key)},
		{Path: "a.txt", Content: []byte(key)},
		{Path: "image.bin", Content: []byte("x\x00" + key)},
	}
	d := testDetector(t, DefaultRules()...)
	report, err := d.ScanFiles(context.Background(), files, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 2 || report.SkippedEntries != 2 || len(report.Findings) != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Findings[0].File != "a.txt" || report.Findings[1].File != "z.txt" {
		t.Fatalf("findings are not ordered: %+v", report.Findings)
	}
	if files[0].Path != "z.txt" {
		t.Fatal("input order was modified")
	}
}

func TestScanFilesRejectsInvalidOrDuplicatePaths(t *testing.T) {
	d := testDetector(t, DefaultRules()...)
	for _, files := range [][]File{
		{{Path: "../outside", Content: []byte("clean")}},
		{{Path: "same.txt"}, {Path: "same.txt"}},
	} {
		report, err := d.ScanFiles(context.Background(), files, Options{})
		if !errors.Is(err, ErrRead) || report.Findings != nil {
			t.Fatalf("report = %+v, error = %v", report, err)
		}
	}
}
