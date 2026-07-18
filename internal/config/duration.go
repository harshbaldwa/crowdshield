package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a YAML string duration with standard time.Duration semantics.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }
func (d Duration) String() string          { return time.Duration(d).String() }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("duration must be a string")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration")
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }
