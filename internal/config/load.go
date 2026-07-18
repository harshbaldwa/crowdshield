package config

import (
	"errors"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Loader reads one bounded strict YAML document and explicit environment overrides.
type Loader struct {
	Version  string
	MaxBytes int64
	Environ  func() []string
}

// DefaultLoader returns the production loader.
func DefaultLoader(version string) Loader {
	return Loader{Version: version, MaxBytes: DefaultMaxConfigBytes, Environ: os.Environ}
}

func decodeCategory(err error) ErrorCategory {
	text := err.Error()
	switch {
	case strings.Contains(text, "invalid CIDR"), strings.Contains(text, "CIDR must"):
		return ErrAllowlist
	case strings.Contains(text, "invalid duration"), strings.Contains(text, "duration must"):
		return ErrDuration
	default:
		return ErrYAML
	}
}

// Load reads, overrides, canonicalizes, and validates a configuration file.
func (l Loader) Load(path string) (Config, error) {
	if path == "" {
		path = DefaultPath
	}
	maxBytes := l.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxConfigBytes
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, configError(ErrPath, "config", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return Config{}, configError(ErrPath, "config", err)
	}
	if stat.Size() > maxBytes {
		return Config{}, configError(ErrConfigSize, "config", nil)
	}

	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return Config{}, configError(ErrYAML, "config", err)
	}
	if int64(len(body)) > maxBytes {
		return Config{}, configError(ErrConfigSize, "config", nil)
	}

	cfg := Defaults(l.Version)
	decoder := yaml.NewDecoder(strings.NewReader(string(body)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, configError(ErrYAML, "config", err)
		}
		return Config{}, configError(decodeCategory(err), "config", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, configError(ErrYAMLDocument, "config", err)
	}

	environ := os.Environ
	if l.Environ != nil {
		environ = l.Environ
	}
	if err := applyEnvironment(&cfg, environ()); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
