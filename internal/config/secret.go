package config

import "go.yaml.in/yaml/v3"

// Secret prevents accidental formatting of sensitive configuration values.
// Reveal should be called only at the final protocol boundary.
type Secret struct {
	value string
}

func NewSecret(value string) Secret { return Secret{value: value} }
func (s Secret) IsSet() bool        { return s.value != "" }
func (s Secret) Reveal() string     { return s.value }
func (s Secret) String() string     { return "[REDACTED]" }
func (s Secret) GoString() string   { return "config.Secret{[REDACTED]}" }
func (s Secret) MarshalText() ([]byte, error) {
	return []byte("[REDACTED]"), nil
}
func (s Secret) MarshalYAML() (any, error) {
	return "[REDACTED]", nil
}

var _ yaml.Marshaler = Secret{}
