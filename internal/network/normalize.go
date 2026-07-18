package network

import (
	"errors"
	"net/netip"
	"strings"
)

var ErrInvalidNetwork = errors.New("invalid network indicator")

type Kind uint8

const (
	KindInvalid Kind = iota
	KindIP
	KindRange
)

// NormalizeAddress parses a single address and canonicalizes IPv4-mapped IPv6.
func NormalizeAddress(raw string) (netip.Addr, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return netip.Addr{}, ErrInvalidNetwork
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, ErrInvalidNetwork
	}
	return addr.Unmap(), nil
}

// NormalizePrefix parses, unmapps, and masks a CIDR. A mapped-IPv4 prefix may
// only cover bits within the mapped /96 region.
func NormalizePrefix(raw string) (netip.Prefix, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return netip.Prefix{}, ErrInvalidNetwork
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, ErrInvalidNetwork
	}
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, ErrInvalidNetwork
		}
		prefix = netip.PrefixFrom(addr.Unmap(), bits-96)
	}
	return prefix.Masked(), nil
}

// ParseValue distinguishes a bare address from a CIDR without expanding it.
func ParseValue(raw string) (netip.Prefix, Kind, error) {
	if strings.Contains(raw, "/") {
		prefix, err := NormalizePrefix(raw)
		if err != nil {
			return netip.Prefix{}, KindInvalid, err
		}
		return prefix, KindRange, nil
	}
	addr, err := NormalizeAddress(raw)
	if err != nil {
		return netip.Prefix{}, KindInvalid, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), KindIP, nil
}

func ValidateKind(prefix netip.Prefix, kind Kind) error {
	if !prefix.IsValid() || prefix != prefix.Masked() {
		return ErrInvalidNetwork
	}
	switch kind {
	case KindIP:
		if prefix.Bits() != prefix.Addr().BitLen() {
			return ErrInvalidNetwork
		}
	case KindRange:
	default:
		return ErrInvalidNetwork
	}
	return nil
}
