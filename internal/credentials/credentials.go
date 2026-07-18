// Package credentials loads dedicated CrowdSec machine credentials without
// exposing them through formatting or diagnostic errors.
package credentials

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

const DefaultMaxBytes = int64(64 << 10)

type Loader struct {
	MaxBytes          int64
	StrictPermissions bool
	AllowedHTTPHosts  []string
}

type rawCredentials struct {
	URL      string `yaml:"url"`
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
}

// Credentials keeps its fields private and deliberately implements redacted
// formatting. Callers should reveal values only while constructing a request.
type Credentials struct {
	endpoint *url.URL
	login    string
	password []byte
}

func (c *Credentials) String() string   { return "CrowdSec credentials [REDACTED]" }
func (c *Credentials) GoString() string { return "credentials.Credentials{[REDACTED]}" }

func (c *Credentials) Endpoint() *url.URL {
	if c == nil || c.endpoint == nil {
		return &url.URL{}
	}
	clone := *c.endpoint
	return &clone
}

func (c *Credentials) Login() string {
	if c == nil {
		return ""
	}
	return c.login
}

func (c *Credentials) Password() string {
	if c == nil {
		return ""
	}
	return string(c.password)
}

// Destroy clears mutable secret memory. Go strings created by Password cannot
// be retroactively cleared, so callers must keep them short-lived.
func (c *Credentials) Destroy() {
	if c == nil {
		return
	}
	for i := range c.password {
		c.password[i] = 0
	}
	c.password = nil
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) }) >= 0
}

func (l Loader) validateURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" {
		return nil, credentialError(ErrURL, err)
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || hasControl(parsed.Host) {
		return nil, credentialError(ErrURL, nil)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		allowed := slices.ContainsFunc(l.AllowedHTTPHosts, func(host string) bool {
			return strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(parsed.Hostname(), "."))
		})
		if !allowed {
			return nil, credentialError(ErrURL, nil)
		}
	default:
		return nil, credentialError(ErrURL, nil)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func (l Loader) Load(path string) (*Credentials, error) {
	maxBytes := l.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, credentialError(ErrMissing, err)
	}
	if !before.Mode().IsRegular() {
		return nil, credentialError(ErrFileType, nil)
	}
	if l.StrictPermissions && before.Mode().Perm()&0o077 != 0 {
		return nil, credentialError(ErrPermissions, nil)
	}
	if before.Size() > maxBytes {
		return nil, credentialError(ErrSize, nil)
	}

	// #nosec G304 -- the path is operator-selected, lstat-checked, same-file checked, permission-checked, and size-bounded.
	file, err := os.Open(path)
	if err != nil {
		return nil, credentialError(ErrMissing, err)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, credentialError(ErrFileType, err)
	}

	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, credentialError(ErrYAML, err)
	}
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()
	if int64(len(body)) > maxBytes {
		return nil, credentialError(ErrSize, nil)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	var rawCreds rawCredentials
	if err := decoder.Decode(&rawCreds); err != nil {
		return nil, credentialError(ErrYAML, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, credentialError(ErrYAML, err)
	}

	if strings.TrimSpace(rawCreds.URL) == "" || strings.TrimSpace(rawCreds.Login) == "" || rawCreds.Password == "" {
		return nil, credentialError(ErrFields, nil)
	}
	if len(rawCreds.Login) > 128 || hasControl(rawCreds.Login) || len(rawCreds.Password) > 4096 || strings.ContainsRune(rawCreds.Password, '\x00') {
		return nil, credentialError(ErrFields, nil)
	}
	endpoint, err := l.validateURL(rawCreds.URL)
	if err != nil {
		return nil, err
	}

	return &Credentials{
		endpoint: endpoint,
		login:    rawCreds.Login,
		password: []byte(rawCreds.Password),
	}, nil
}
