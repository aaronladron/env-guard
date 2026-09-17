// Package git lit le contenu staged sans modifier le dépôt.
package git

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

var (
	ErrExecutableNotFound = errors.New("git executable not found")
	ErrCommand            = errors.New("git command failed")
	ErrBlobTooLarge       = errors.New("staged file exceeds size limit")
)

type File struct {
	Path    string
	Content []byte
}

type Repository struct {
	executable string
	directory  string
}

func Open(directory string) (*Repository, error) {
	executable, err := exec.LookPath("git")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, ErrExecutableNotFound
		}
		return nil, ErrCommand
	}
	return &Repository{executable: executable, directory: directory}, nil
}

// Staged renvoie les fichiers réguliers ajoutés, copiés, modifiés ou renommés.
// Les suppressions, sous-modules et liens symboliques ne contiennent rien à analyser.
func (r *Repository) Staged(ctx context.Context, maxBytes int64) ([]File, error) {
	if r == nil || r.executable == "" || maxBytes < 0 {
		return nil, ErrCommand
	}
	changed, err := r.output(ctx, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", "--")
	if err != nil {
		return nil, err
	}
	wanted, err := nulSet(changed)
	if err != nil {
		return nil, err
	}
	if len(wanted) == 0 {
		return []File{}, nil
	}
	index, err := r.output(ctx, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	entries, err := indexEntries(index, wanted)
	if err != nil {
		return nil, err
	}
	files := make([]File, 0, len(entries))
	for _, entry := range entries {
		if entry.mode != "100644" && entry.mode != "100755" {
			continue
		}
		sizeOutput, err := r.output(ctx, "cat-file", "-s", entry.object)
		if err != nil {
			return nil, err
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64)
		if err != nil || size < 0 {
			return nil, ErrCommand
		}
		if size > maxBytes {
			return nil, ErrBlobTooLarge
		}
		content, err := r.output(ctx, "cat-file", "blob", entry.object)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Path: entry.path, Content: content})
	}
	return files, nil
}

func (r *Repository) output(ctx context.Context, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, r.executable, append([]string{"-C", r.directory}, args...)...).Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrCommand
	}
	return output, nil
}

func nulSet(data []byte) (map[string]bool, error) {
	result := make(map[string]bool)
	for len(data) > 0 {
		end := bytes.IndexByte(data, 0)
		if end < 0 {
			return nil, ErrCommand
		}
		if end > 0 {
			result[string(data[:end])] = true
		}
		data = data[end+1:]
	}
	return result, nil
}

type indexEntry struct {
	mode, object, path string
}

func indexEntries(data []byte, wanted map[string]bool) ([]indexEntry, error) {
	var result []indexEntry
	for len(data) > 0 {
		end := bytes.IndexByte(data, 0)
		if end < 0 {
			return nil, ErrCommand
		}
		record := data[:end]
		data = data[end+1:]
		tab := bytes.IndexByte(record, '\t')
		if tab < 0 {
			return nil, ErrCommand
		}
		fields := strings.Fields(string(record[:tab]))
		path := string(record[tab+1:])
		if len(fields) != 3 {
			return nil, ErrCommand
		}
		if fields[2] == "0" && wanted[path] {
			result = append(result, indexEntry{mode: fields[0], object: fields[1], path: path})
		}
	}
	return result, nil
}
