// Package cli implements the command-line interface independently of process exit.
package cli

import (
	"fmt"
	"io"
)

const (
	ExitOK       = 0
	ExitUsage    = 2
	ExitInternal = 3
)

const help = `env-guard — detect potential secrets before committing to Git

Usage:
  env-guard --help
  env-guard scan
  env-guard scan --help

Commands:
  scan    Scan the current project (not implemented yet)

This initial version provides the CLI only; it cannot detect secrets.
`

const scanHelp = `Usage: env-guard scan

Scan the current project for potential secrets.
Scanning is not implemented yet. No files are inspected.
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
		if len(args) != 1 {
			return usage(stderr)
		}
		// Fail closed: an unfinished scanner must not approve a commit.
		fmt.Fprintln(stderr, "Error: scanning is not implemented yet; no files were scanned.")
		return ExitInternal
	default:
		return usage(stderr)
	}
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
