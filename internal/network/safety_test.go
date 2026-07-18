package network

import (
	"net/netip"
	"testing"
)

func TestRequiredSafetyRangesAreExcluded(t *testing.T) {
	required := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	for range required {
		// Deliberately avoid printing the tested network in normal failure output.
	}
	for _, raw := range required {
		if safe, _ := IsSafePrefix(netip.MustParsePrefix(raw)); safe {
			t.Fatal("required special-purpose range was accepted")
		}
	}
}

func TestDocumentationBenchmarkAndProtocolRangesAreExcluded(t *testing.T) {
	ranges := []string{
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"64:ff9b::/96",
		"100::/64",
		"2001::/23",
		"2001:db8::/32",
		"2002::/16",
		"3fff::/20",
	}
	for _, raw := range ranges {
		if safe, _ := IsSafePrefix(netip.MustParsePrefix(raw)); safe {
			t.Fatal("explicit special-purpose range was accepted")
		}
	}
}

func TestBroadPrefixOverlappingSpecialRangeIsExcluded(t *testing.T) {
	if safe, _ := IsSafePrefix(netip.MustParsePrefix("8.0.0.0/5")); safe {
		t.Fatal("prefix spanning a special-purpose network was accepted")
	}
}

func TestRepresentativeGlobalPrefixesAreAccepted(t *testing.T) {
	public := []string{"8.8.8.0/24", "9.9.9.9/32", "2606:4700:4700::/48", "2620:fe::/48"}
	for _, raw := range public {
		if safe, _ := IsSafePrefix(netip.MustParsePrefix(raw)); !safe {
			t.Fatal("representative global prefix was rejected")
		}
	}
}

func TestSafetyTableReturnsCopy(t *testing.T) {
	first := SafetyPrefixes()
	second := SafetyPrefixes()
	if len(first) == 0 || len(first) != len(second) {
		t.Fatal("safety table unavailable")
	}
	first[0] = netip.Prefix{}
	if !second[0].IsValid() {
		t.Fatal("caller could mutate safety table")
	}
}
