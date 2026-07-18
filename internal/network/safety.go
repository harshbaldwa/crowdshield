package network

import (
	"net/netip"
	"slices"
)

type SafetyReason string

const (
	SafetyInvalid SafetyReason = "invalid"
	SafetySpecial SafetyReason = "special_purpose"
)

// safetyPrefixes is a conservative static subset of the IANA special-purpose
// registries plus documentation, benchmarking, translation, and transition
// ranges. Any overlap is rejected so a broad feed prefix cannot include a
// protected local/special network as collateral.
var safetyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func SafetyPrefixes() []netip.Prefix { return slices.Clone(safetyPrefixes) }

func IsSafePrefix(prefix netip.Prefix) (bool, SafetyReason) {
	if !prefix.IsValid() || prefix != prefix.Masked() || !prefix.Addr().IsGlobalUnicast() {
		return false, SafetyInvalid
	}
	for _, special := range safetyPrefixes {
		if prefix.Overlaps(special) {
			return false, SafetySpecial
		}
	}
	return true, ""
}
