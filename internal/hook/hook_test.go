package hook

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallStandaloneIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "pre-commit")
	result, err := Install(path, false)
	if err != nil || result.AlreadyInstalled || result.Wrapped {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
	before := readFile(t, path)
	if !strings.Contains(before, "env-guard scan --staged") {
		t.Fatalf("unexpected hook: %q", before)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatal("hook is not executable")
		}
	}
	result, err = Install(path, false)
	if err != nil || !result.AlreadyInstalled || result.Wrapped {
		t.Fatalf("second install = %+v, %v", result, err)
	}
	if after := readFile(t, path); after != before {
		t.Fatal("idempotent install changed the hook")
	}
}

func TestExistingHookRequiresExplicitWrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-commit")
	original := "#!/usr/bin/env python3\nprint('existing')\n"
	writeFile(t, path, original, 0o744)
	if _, err := Install(path, false); !errors.Is(err, ErrExistingHook) {
		t.Fatalf("error = %v", err)
	}
	if got := readFile(t, path); got != original {
		t.Fatal("existing hook was modified")
	}
}

func TestWrapAndRemoveRestoresExistingHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-commit")
	original := "#!/bin/sh\necho existing\n"
	writeFile(t, path, original, 0o744)
	result, err := Install(path, true)
	if err != nil || !result.Wrapped || result.AlreadyInstalled {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
	if got := readFile(t, backupPath(path)); got != original {
		t.Fatalf("backup = %q", got)
	}
	wrapper := readFile(t, path)
	if !strings.Contains(wrapper, `"$0.env-guard-backup" "$@"`) || !strings.Contains(wrapper, "env-guard scan --staged") {
		t.Fatalf("unexpected wrapper: %q", wrapper)
	}
	result, err = Install(path, true)
	if err != nil || !result.Wrapped || !result.AlreadyInstalled {
		t.Fatalf("second install = %+v, %v", result, err)
	}
	restored, err := Remove(path)
	if err != nil || !restored {
		t.Fatalf("restored = %v, error = %v", restored, err)
	}
	if got := readFile(t, path); got != original {
		t.Fatalf("restored hook = %q", got)
	}
	if _, err := os.Stat(backupPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup still exists: %v", err)
	}
}

func TestRemoveStandalone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-commit")
	if _, err := Install(path, false); err != nil {
		t.Fatal(err)
	}
	restored, err := Remove(path)
	if err != nil || restored {
		t.Fatalf("restored = %v, error = %v", restored, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hook still exists: %v", err)
	}
}

func TestHookConflicts(t *testing.T) {
	t.Run("backup exists", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pre-commit")
		writeFile(t, path, "#!/bin/sh\n", 0o755)
		writeFile(t, backupPath(path), "backup", 0o600)
		if _, err := Install(path, true); !errors.Is(err, ErrBackupExists) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("unmanaged removal", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pre-commit")
		writeFile(t, path, "#!/bin/sh\n", 0o755)
		if _, err := Remove(path); !errors.Is(err, ErrNotInstalled) {
			t.Fatalf("error = %v", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("symbolic link", func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "target")
			writeFile(t, target, "#!/bin/sh\n", 0o755)
			path := filepath.Join(directory, "pre-commit")
			if err := os.Symlink(target, path); err != nil {
				t.Skipf("cannot create symbolic link: %v", err)
			}
			if _, err := Install(path, true); !errors.Is(err, ErrInvalidHook) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
