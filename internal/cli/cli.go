// Package cli implements the command-line interface independently of process exit.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aaronladron/env-guard/internal/config"
	gitrepo "github.com/aaronladron/env-guard/internal/git"
	"github.com/aaronladron/env-guard/internal/hook"
	"github.com/aaronladron/env-guard/internal/output"
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
  env-guard scan [--staged] [--json] [--exclude MOTIF]
  env-guard init [--wrap | --remove]
  env-guard scan --help

Commands:
  scan    Scan the current project
  init    Manage the Git pre-commit hook
`

const initHelp = `Usage: env-guard init [--wrap | --remove]

Install the env-guard pre-commit hook.

Options:
  --wrap      Preserve and run an existing hook before env-guard
  --remove    Remove env-guard and restore a preserved hook
`

const scanHelp = `Usage: env-guard scan [--staged] [--json] [--exclude MOTIF]

Scan the current project for potential secrets.

Options:
  --staged          Scan only the content staged in Git
  --json            Write the stable JSON format
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
	case "init":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			return write(stdout, stderr, initHelp)
		}
		return runInit(args[1:], stdout, stderr)
	default:
		return usage(stderr)
	}
}

func runInit(args []string, stdout, stderr io.Writer) int {
	wrap, remove := false, false
	for _, arg := range args {
		switch arg {
		case "--wrap":
			if wrap || remove {
				return usage(stderr)
			}
			wrap = true
		case "--remove":
			if remove || wrap {
				return usage(stderr)
			}
			remove = true
		default:
			return usage(stderr)
		}
	}
	repository, err := gitrepo.Open(".")
	if errors.Is(err, gitrepo.ErrExecutableNotFound) {
		fmt.Fprintln(stderr, "Error: Git executable not found")
		return ExitInternal
	}
	if err != nil {
		fmt.Fprintln(stderr, "Error: unable to initialize Git hook.")
		return ExitInternal
	}
	path, err := repository.PreCommitHookPath(context.Background())
	if err != nil {
		fmt.Fprintln(stderr, "Error: current directory is not a Git repository.")
		return ExitInternal
	}
	if remove {
		restored, err := hook.Remove(path)
		if errors.Is(err, hook.ErrNotInstalled) {
			fmt.Fprintln(stderr, "Error: env-guard pre-commit hook is not installed.")
			return ExitUsage
		}
		if err != nil {
			fmt.Fprintln(stderr, "Error: unable to remove the pre-commit hook.")
			return ExitInternal
		}
		message := "env-guard pre-commit hook removed."
		if restored {
			message = "env-guard pre-commit hook removed; previous hook restored."
		}
		return write(stdout, stderr, message+"\n")
	}
	result, err := hook.Install(path, wrap)
	if errors.Is(err, hook.ErrExistingHook) {
		fmt.Fprintln(stderr, "Error: a pre-commit hook already exists.")
		fmt.Fprintln(stderr, "Run 'env-guard init --wrap' to preserve it and install env-guard safely.")
		return ExitUsage
	}
	if errors.Is(err, hook.ErrBackupExists) {
		fmt.Fprintln(stderr, "Error: an env-guard hook backup already exists; no files were changed.")
		return ExitInternal
	}
	if err != nil {
		fmt.Fprintln(stderr, "Error: unable to install the pre-commit hook.")
		return ExitInternal
	}
	if result.AlreadyInstalled {
		return write(stdout, stderr, "env-guard pre-commit hook is already installed.\n")
	}
	if result.Wrapped {
		return write(stdout, stderr, "env-guard pre-commit hook installed; previous hook preserved.\n")
	}
	return write(stdout, stderr, "env-guard pre-commit hook installed.\n")
}

func runScan(args []string, stdout, stderr io.Writer) int {
	options, ok := scanArgs(args)
	if !ok {
		return usage(stderr)
	}
	configuration, _, err := config.Load(config.DefaultPath)
	if err != nil {
		fmt.Fprintln(stderr, "Error: invalid .env-guard.yaml configuration.")
		return ExitInternal
	}
	rules, ok := configuredRules(scanner.DefaultRules(), configuration.IgnoreRules)
	if !ok {
		fmt.Fprintln(stderr, "Error: invalid .env-guard.yaml configuration.")
		return ExitInternal
	}
	detector, err := scanner.NewDetector(rules)
	if err != nil {
		fmt.Fprintln(stderr, "Error: unable to initialize detection rules.")
		return ExitInternal
	}
	ctx := context.Background()
	scanOptions := scanner.Options{
		Exclude:   append(append([]string{}, configuration.Exclude...), options.excludes...),
		Allowlist: make([]scanner.AllowEntry, 0, len(configuration.Allowlist)),
	}
	for _, entry := range configuration.Allowlist {
		scanOptions.Allowlist = append(scanOptions.Allowlist, scanner.AllowEntry{Path: entry.Path, Line: entry.Line, RuleID: entry.Rule})
	}
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
	minimum, ok := scanner.ParseSeverity(configuration.Severity)
	if !ok {
		fmt.Fprintln(stderr, "Error: invalid .env-guard.yaml configuration.")
		return ExitInternal
	}
	report = scanner.FilterSeverity(report, minimum)
	if options.json || configuration.Output == "json" {
		err = output.JSON(stdout, report)
	} else {
		err = output.Human(stdout, report)
	}
	if err != nil {
		fmt.Fprintln(stderr, "Error: unable to write output.")
		return ExitInternal
	}
	if len(report.Findings) > 0 {
		return ExitFindings
	}
	return ExitOK
}

func configuredRules(rules []scanner.Rule, ignored []string) ([]scanner.Rule, bool) {
	known := make(map[string]bool, len(rules))
	for _, rule := range rules {
		known[rule.ID] = true
	}
	disabled := make(map[string]bool, len(ignored))
	for _, id := range ignored {
		if !known[id] {
			return nil, false
		}
		disabled[id] = true
	}
	configured := make([]scanner.Rule, 0, len(rules)-len(disabled))
	for _, rule := range rules {
		if !disabled[rule.ID] {
			configured = append(configured, rule)
		}
	}
	return configured, len(configured) > 0
}

type parsedScanOptions struct {
	excludes []string
	staged   bool
	json     bool
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
		case args[i] == "--json":
			if options.json {
				return parsedScanOptions{}, false
			}
			options.json = true
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
