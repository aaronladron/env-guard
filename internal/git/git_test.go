package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStagedReadsIndexInsteadOfWorkingTree(t *testing.T) {
	executable, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	directory := t.TempDir()
	runGit(t, executable, directory, "init", "--quiet")
	stagedValue := "AKIA" + strings.Repeat("A", 16)
	writeFile(t, directory, "staged.txt", "key="+stagedValue+"\n")
	writeFile(t, directory, "clean.txt", "port=8080\n")
	runGit(t, executable, directory, "add", "staged.txt", "clean.txt")
	writeFile(t, directory, "staged.txt", "working tree is clean\n")
	writeFile(t, directory, "untracked.txt", "key="+stagedValue+"\n")

	repository := &Repository{executable: executable, directory: directory}
	files, err := repository.Staged(context.Background(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d, want 2", len(files))
	}
	contents := make(map[string]string)
	for _, file := range files {
		contents[file.Path] = string(file.Content)
	}
	if contents["staged.txt"] != "key="+stagedValue+"\n" {
		t.Fatalf("staged content = %q", contents["staged.txt"])
	}
	if _, ok := contents["untracked.txt"]; ok {
		t.Fatal("untracked file was returned")
	}
}

func TestStagedSkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic link setup is platform-dependent")
	}
	executable, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	directory := t.TempDir()
	runGit(t, executable, directory, "init", "--quiet")
	writeFile(t, directory, "target.txt", "clean\n")
	if err := os.Symlink("target.txt", filepath.Join(directory, "link.txt")); err != nil {
		t.Skipf("cannot create symbolic link: %v", err)
	}
	runGit(t, executable, directory, "add", "link.txt")
	repository := &Repository{executable: executable, directory: directory}
	files, err := repository.Staged(context.Background(), 1024)
	if err != nil || len(files) != 0 {
		t.Fatalf("files = %v, error = %v", files, err)
	}
}

func TestStagedUsesNewPathForRenameAndOmitsDeletion(t *testing.T) {
	executable, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	directory := t.TempDir()
	runGit(t, executable, directory, "init", "--quiet")
	writeFile(t, directory, "old.txt", "content\n")
	writeFile(t, directory, "deleted.txt", "content\n")
	runGit(t, executable, directory, "add", "old.txt", "deleted.txt")
	runGit(t, executable, directory, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "base")
	if err := os.Rename(filepath.Join(directory, "old.txt"), filepath.Join(directory, "new.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	runGit(t, executable, directory, "add", "-A")
	repository := &Repository{executable: executable, directory: directory}
	files, err := repository.Staged(context.Background(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "new.txt" || string(files[0].Content) != "content\n" {
		t.Fatalf("unexpected files: %+v", files)
	}
}

func TestOpenWithoutGit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := Open("."); !errors.Is(err, ErrExecutableNotFound) {
		t.Fatalf("error = %v", err)
	}
}

func TestStagedFailures(t *testing.T) {
	executable, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	t.Run("not a repository", func(t *testing.T) {
		repository := &Repository{executable: executable, directory: t.TempDir()}
		if _, err := repository.Staged(context.Background(), 1024); !errors.Is(err, ErrCommand) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("size limit", func(t *testing.T) {
		directory := t.TempDir()
		runGit(t, executable, directory, "init", "--quiet")
		writeFile(t, directory, "large.txt", strings.Repeat("a", 20))
		runGit(t, executable, directory, "add", "large.txt")
		repository := &Repository{executable: executable, directory: directory}
		if _, err := repository.Staged(context.Background(), 10); !errors.Is(err, ErrBlobTooLarge) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		repository := &Repository{executable: executable, directory: t.TempDir()}
		if _, err := repository.Staged(ctx, 1024); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestParsingRejectsTruncatedOutput(t *testing.T) {
	if _, err := nulSet([]byte("missing terminator")); !errors.Is(err, ErrCommand) {
		t.Fatalf("error = %v", err)
	}
	if _, err := indexEntries([]byte("100644 object 0 missing-tab\x00"), map[string]bool{}); !errors.Is(err, ErrCommand) {
		t.Fatalf("error = %v", err)
	}
}

func runGit(t *testing.T, executable, directory string, args ...string) {
	t.Helper()
	command := exec.Command(executable, append([]string{"-C", directory}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func writeFile(t *testing.T, directory, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
