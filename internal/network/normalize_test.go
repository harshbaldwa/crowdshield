package network

import (
	"net/netip"
	"testing"
)

func TestNormalizeAddressAndPrefix(t *testing.T) {
	addr, err := NormalizeAddress("192.0.2.129")
	if err != nil || !addr.Is4() {
		t.Fatal("IPv4 address normalization failed")
	}
	mapped, err := NormalizeAddress("::ffff:192.0.2.129")
	if err != nil || !mapped.Is4() || mapped != addr {
		t.Fatal("mapped IPv4 normalization failed")
	}
	prefix, err := NormalizePrefix("192.0.2.129/24")
	if err != nil || prefix.Bits() != 24 || prefix.Addr() != netip.MustParseAddr("192.0.2.0") {
		t.Fatal("IPv4 prefix was not masked")
	}
	v6, err := NormalizePrefix("2606:4700:4700:1::99/64")
	if err != nil || v6.Bits() != 64 || v6.Addr() != netip.MustParseAddr("2606:4700:4700:1::") {
		t.Fatal("IPv6 prefix was not masked")
	}
	mappedPrefix, err := NormalizePrefix("::ffff:192.0.2.129/120")
	if err != nil || !mappedPrefix.Addr().Is4() || mappedPrefix.Bits() != 24 {
		t.Fatal("mapped IPv4 prefix normalization failed")
	}
}

func TestNormalizeRejectsInvalidMappedNetwork(t *testing.T) {
	if _, err := NormalizePrefix("::ffff:0:0/95"); err == nil {
		t.Fatal("mapped prefix crossing the IPv4 boundary accepted")
	}
}

func TestKindValidation(t *testing.T) {
	full := netip.MustParsePrefix("8.8.8.8/32")
	if err := ValidateKind(full, KindIP); err != nil {
		t.Fatal("full-width host rejected")
	}
	if err := ValidateKind(netip.MustParsePrefix("8.8.8.0/24"), KindIP); err == nil {
		t.Fatal("network accepted as individual address")
	}
	if err := ValidateKind(full, KindRange); err != nil {
		t.Fatal("full-width CIDR rejected as range")
	}
}
