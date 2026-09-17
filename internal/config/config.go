// Package config charge la configuration locale d'env-guard.
package config

import (
	"errors"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultPath    = ".env-guard.yaml"
	maxConfigBytes = 1024 * 1024
)

var (
	ErrInvalid  = errors.New("invalid env-guard configuration")
	ErrRead     = errors.New("unable to read env-guard configuration")
	ErrTooLarge = errors.New("env-guard configuration exceeds 1 MiB")
)

type AllowEntry struct {
	Path string `yaml:"path"`
	Line int    `yaml:"line"`
	Rule string `yaml:"rule"`
}

type Config struct {
	Exclude     []string     `yaml:"exclude"`
	IgnoreRules []string     `yaml:"ignore_rules"`
	Allowlist   []AllowEntry `yaml:"allowlist"`
	Severity    string       `yaml:"severity"`
	Output      string       `yaml:"output"`
}

func Defaults() Config {
	return Config{Severity: "low", Output: "human"}
}

// Load renvoie la configuration par défaut si le fichier n'existe pas.
func Load(path string) (Config, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), false, nil
	}
	if err != nil {
		return Config{}, false, ErrRead
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Config{}, false, ErrRead
	}
	if info.Size() > maxConfigBytes {
		return Config{}, false, ErrTooLarge
	}
	limited := io.LimitReader(file, maxConfigBytes+1)
	decoder := yaml.NewDecoder(limited)
	decoder.KnownFields(true)
	config := Defaults()
	decodeErr := decoder.Decode(&config)
	if decodeErr != nil && decodeErr != io.EOF {
		return Config{}, false, ErrInvalid
	}
	if decodeErr == nil {
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return Config{}, false, ErrInvalid
		}
	}
	if err := validate(&config); err != nil {
		return Config{}, false, err
	}
	return config, true, nil
}

func validate(config *Config) error {
	config.Severity = strings.ToLower(strings.TrimSpace(config.Severity))
	config.Output = strings.ToLower(strings.TrimSpace(config.Output))
	switch config.Severity {
	case "low", "medium", "high":
	default:
		return ErrInvalid
	}
	switch config.Output {
	case "human", "json":
	default:
		return ErrInvalid
	}
	seenRules := make(map[string]bool, len(config.IgnoreRules))
	for _, rule := range config.IgnoreRules {
		if strings.TrimSpace(rule) == "" || seenRules[rule] {
			return ErrInvalid
		}
		seenRules[rule] = true
	}
	for _, entry := range config.Allowlist {
		if strings.TrimSpace(entry.Path) == "" || entry.Line < 1 || strings.TrimSpace(entry.Rule) == "" {
			return ErrInvalid
		}
	}
	return nil
}
