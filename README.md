# env-guard

A Go CLI intended to detect potential secrets before they are committed to Git.

**Development status: step 1 only.** The CLI and its tests are available. Secret
detection is not implemented; this version must not be used as a security check.

## Build and run

Requires Go 1.27 or newer. No external Go dependencies are needed.

```sh
go build -o bin/env-guard ./cmd/env-guard
./bin/env-guard --help
./bin/env-guard scan
```

On Windows, build with `-o bin/env-guard.exe` and run that executable.

`scan` currently writes the following message to stderr and exits with code 3:

```text
Error: scanning is not implemented yet; no files were scanned.
```

This deliberately avoids reporting a successful security scan before the engine
exists. `scan --help` displays command help and exits successfully. Unknown flags,
commands and positional arguments are rejected, including `--staged` for now.

## Current exit codes

| Code | Meaning |
| --- | --- |
| 0 | Help displayed successfully |
| 2 | Invalid command or arguments |
| 3 | Scan unavailable or output failure |

Code 1 will be introduced with secret detection. No successful scan is possible yet.

## Development

```sh
go test ./...
go vet ./...
go fmt ./...
```

`cmd/env-guard` only handles process exit. `internal/cli` handles arguments and
output through injected writers, so behavior can be tested without exiting the
test process. The standard library is sufficient for this initial command set.
Scanner, rules, Git integration, configuration and release automation will be
added in subsequent steps.
