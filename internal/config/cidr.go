package config

import (
	"fmt"
	"net/netip"

	"go.yaml.in/yaml/v3"
)

// CIDR is a canonical network prefix. Bare addresses are intentionally invalid.
type CIDR struct {
	prefix netip.Prefix
}

func (c CIDR) Prefix() netip.Prefix { return c.prefix }
func (c CIDR) String() string       { return c.prefix.String() }

func (c *CIDR) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("CIDR must be a string")
	}
	prefix, err := netip.ParsePrefix(node.Value)
	if err != nil {
		return fmt.Errorf("invalid CIDR")
	}
	c.prefix = prefix.Masked()
	return nil
}

func (c CIDR) MarshalYAML() (any, error) { return c.String(), nil }
