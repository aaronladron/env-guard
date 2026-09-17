// Package cli implements the command-line interface independently of process exit.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	gitrepo "github.com/aaronladron/env-guard/internal/git"
	"github.com/aaronladron/env-guard/internal/scanner"
)

const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
	ExitInternal = 3
)

const help = `env-guard — detect potential secrets before committing to Git

Usage:
  env-guard --help
  env-guard scan [--staged] [--exclude MOTIF]
  env-guard scan --help

Commands:
  scan    Scan the current project
`

const scanHelp = `Usage: env-guard scan [--staged] [--exclude MOTIF]

Scan the current project for potential secrets.

Options:
  --staged          Scan only the content staged in Git
  --exclude MOTIF    Exclude a name or relative path (repeatable)
`

// Run executes a command and returns its process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return write(stdout, stderr, help)
	}
	switch args[0] {
	case "--help", "-h", "help":
		if len(args) != 1 {
			return usage(stderr)
		}
		return write(stdout, stderr, help)
	case "scan":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			return write(stdout, stderr, scanHelp)
		}
		return runScan(args[1:], stdout, stderr)
	default:
		return usage(stderr)
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	options, ok := scanArgs(args)
	if !ok {
		return usage(stderr)
	}
	detector, err := scanner.NewDetector(scanner.DefaultRules())
	if err != nil {
		fmt.Fprintln(stderr, "Error: unable to initialize detection rules.")
		return ExitInternal
	}
	ctx := context.Background()
	scanOptions := scanner.Options{Exclude: options.excludes}
	var report scanner.Report
	if options.staged {
		repository, gitErr := gitrepo.Open(".")
		if errors.Is(gitErr, gitrepo.ErrExecutableNotFound) {
			fmt.Fprintln(stderr, "Error: Git executable not found")
			return ExitInternal
		}
		if gitErr != nil {
			fmt.Fprintln(stderr, "Error: unable to initialize Git scan.")
			return ExitInternal
		}
		staged, gitErr := repository.Staged(ctx, scanner.MaxFileBytes)
		if gitErr != nil {
			fmt.Fprintln(stderr, "Error: unable to read staged Git files.")
			return ExitInternal
		}
		files := make([]scanner.File, len(staged))
		for i, file := range staged {
			files[i] = scanner.File{Path: file.Path, Content: file.Content}
		}
		report, err = detector.ScanFiles(ctx, files, scanOptions)
	} else {
		root, openErr := os.OpenRoot(".")
		if openErr != nil {
			fmt.Fprintln(stderr, "Error: unable to open the current directory.")
			return ExitInternal
		}
		defer root.Close()
		report, err = detector.ScanFS(ctx, root.FS(), scanOptions)
	}
	if err != nil {
		if errors.Is(err, scanner.ErrInvalidOptions) {
			return usage(stderr)
		}
		fmt.Fprintln(stderr, "Error: scan failed.")
		return ExitInternal
	}
	if _, err := fmt.Fprintf(stdout, "env-guard\n\n%d files scanned\n", report.FilesScanned); err != nil {
		fmt.Fprintln(stderr, "Error: unable to write output.")
		return ExitInternal
	}
	if len(report.Findings) == 0 {
		if _, err := fmt.Fprintln(stdout, "No potential secrets detected."); err != nil {
			fmt.Fprintln(stderr, "Error: unable to write output.")
			return ExitInternal
		}
		return ExitOK
	}
	if _, err := fmt.Fprintf(stdout, "\n%d potential secrets detected\n", len(report.Findings)); err != nil {
		fmt.Fprintln(stderr, "Error: unable to write output.")
		return ExitInternal
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(stdout, "\n%s  %s\n    %s:%d\n    Value: %s\n", finding.Severity, finding.Type, finding.File, finding.Line, finding.MaskedValue); err != nil {
			fmt.Fprintln(stderr, "Error: unable to write output.")
			return ExitInternal
		}
	}
	return ExitFindings
}

type parsedScanOptions struct {
	excludes []string
	staged   bool
}

func scanArgs(args []string) (parsedScanOptions, bool) {
	var options parsedScanOptions
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--staged":
			if options.staged {
				return parsedScanOptions{}, false
			}
			options.staged = true
		case args[i] == "--exclude":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return parsedScanOptions{}, false
			}
			i++
			options.excludes = append(options.excludes, args[i])
		case strings.HasPrefix(args[i], "--exclude="):
			value := strings.TrimPrefix(args[i], "--exclude=")
			if value == "" {
				return parsedScanOptions{}, false
			}
			options.excludes = append(options.excludes, value)
		default:
			return parsedScanOptions{}, false
		}
	}
	return options, true
}

func usage(stderr io.Writer) int {
	fmt.Fprintln(stderr, "Error: unsupported command or arguments. Run 'env-guard --help' for usage.")
	return ExitUsage
}

func write(stdout, stderr io.Writer, text string) int {
	if _, err := io.WriteString(stdout, text); err != nil {
		fmt.Fprintln(stderr, "Error: unable to write output.")
		return ExitInternal
	}
	return ExitOK
}
