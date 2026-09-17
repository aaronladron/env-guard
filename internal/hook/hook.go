// Package hook installe et retire le hook pre-commit géré par env-guard.
package hook

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrExistingHook   = errors.New("pre-commit hook already exists")
	ErrBackupExists   = errors.New("pre-commit hook backup already exists")
	ErrNotInstalled   = errors.New("env-guard hook is not installed")
	ErrInvalidHook    = errors.New("pre-commit hook is not a regular file")
	ErrUnexpectedMode = errors.New("env-guard hook has an unknown mode")
)

const (
	standaloneMarker = "# env-guard-hook: standalone"
	wrappedMarker    = "# env-guard-hook: wrapped"
	maxHookBytes     = 1024 * 1024
)

type InstallResult struct {
	AlreadyInstalled bool
	Wrapped          bool
}

func Install(path string, wrap bool) (InstallResult, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return InstallResult{}, err
		}
		if err := writeNew(path, standaloneScript()); err != nil {
			return InstallResult{}, err
		}
		return InstallResult{}, nil
	}
	if err != nil {
		return InstallResult{}, err
	}
	if !info.Mode().IsRegular() {
		return InstallResult{}, ErrInvalidHook
	}
	mode, err := readMode(path)
	if err != nil {
		return InstallResult{}, err
	}
	if mode != "" {
		return InstallResult{AlreadyInstalled: true, Wrapped: mode == "wrapped"}, nil
	}
	if !wrap {
		return InstallResult{}, ErrExistingHook
	}
	backup := backupPath(path)
	if _, err := os.Lstat(backup); err == nil {
		return InstallResult{}, ErrBackupExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return InstallResult{}, err
	}
	if err := os.Rename(path, backup); err != nil {
		return InstallResult{}, err
	}
	if err := writeNew(path, wrappedScript()); err != nil {
		if restoreErr := os.Rename(backup, path); restoreErr != nil {
			return InstallResult{}, fmt.Errorf("install hook: %w; restore hook: %v", err, restoreErr)
		}
		return InstallResult{}, err
	}
	return InstallResult{Wrapped: true}, nil
}

func Remove(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, ErrNotInstalled
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, ErrInvalidHook
	}
	mode, err := readMode(path)
	if err != nil {
		return false, err
	}
	switch mode {
	case "standalone":
		return false, os.Remove(path)
	case "wrapped":
		backup := backupPath(path)
		backupInfo, err := os.Lstat(backup)
		if err != nil {
			return false, err
		}
		if !backupInfo.Mode().IsRegular() {
			return false, ErrInvalidHook
		}
		if err := os.Remove(path); err != nil {
			return false, err
		}
		if err := os.Rename(backup, path); err != nil {
			return false, err
		}
		return true, nil
	case "":
		return false, ErrNotInstalled
	default:
		return false, ErrUnexpectedMode
	}
}

func backupPath(path string) string {
	return path + ".env-guard-backup"
}

func readMode(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxHookBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(data) > maxHookBytes {
		return "", ErrInvalidHook
	}
	switch {
	case bytes.HasPrefix(data, []byte("#!/bin/sh\n"+standaloneMarker+"\n")):
		return "standalone", nil
	case bytes.HasPrefix(data, []byte("#!/bin/sh\n"+wrappedMarker+"\n")):
		return "wrapped", nil
	default:
		return "", nil
	}
}

func writeNew(path, content string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, content)
	chmodErr := file.Chmod(0o755)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || chmodErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if writeErr != nil {
			return writeErr
		}
		if chmodErr != nil {
			return chmodErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return nil
}

func standaloneScript() string {
	return "#!/bin/sh\n" + standaloneMarker + "\nset -u\nenv-guard scan --staged\n"
}

func wrappedScript() string {
	return "#!/bin/sh\n" + wrappedMarker + "\nset -u\n\"$0.env-guard-backup\" \"$@\" || exit $?\nenv-guard scan --staged\n"
}
