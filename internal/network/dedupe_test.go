package network

import (
	"net/netip"
	"testing"
)

func candidate(raw string, kind Kind, id int64, name string, order int) Candidate {
	prefix, err := NormalizePrefix(raw)
	if err != nil {
		panic("invalid static test candidate")
	}
	return Candidate{Prefix: prefix, Kind: kind, FeedID: id, FeedName: name, FeedOrder: order}
}

func objectByPrefix(t *testing.T, objects []Object, raw string) Object {
	t.Helper()
	prefix := netip.MustParsePrefix(raw).Masked()
	for _, object := range objects {
		if object.Prefix == prefix {
			return object
		}
	}
	t.Fatal("expected object missing")
	return Object{}
}

func TestBuildDesiredDeduplicatesExactlyAndPreservesProvenance(t *testing.T) {
	objects, summary := BuildDesired([]Candidate{
		candidate("8.8.8.8/32", KindRange, 1, "feed-one", 0),
		candidate("8.8.8.8/32", KindRange, 2, "feed-two", 1),
		candidate("8.8.8.8/32", KindRange, 1, "feed-one", 0),
	}, nil)
	if len(objects) != 1 || summary.ExactDuplicates != 2 {
		t.Fatal("exact duplicate enforcement was not collapsed")
	}
	if len(objects[0].Contributors) != 2 || objects[0].Scope != ScopeRange || !objects[0].Desired {
		t.Fatal("duplicate provenance or range scope was lost")
	}
}

func TestBareHostWinsScopeForExactHostNetwork(t *testing.T) {
	objects, _ := BuildDesired([]Candidate{
		candidate("8.8.4.4/32", KindRange, 1, "feed-one", 0),
		candidate("8.8.4.4/32", KindIP, 2, "feed-two", 1),
	}, nil)
	if len(objects) != 1 || objects[0].Scope != ScopeIP || len(objects[0].Contributors) != 2 {
		t.Fatal("host/range duplicate did not choose deterministic IP scope")
	}
}

func TestHostCoveredByImportedRangeIsSuppressed(t *testing.T) {
	objects, summary := BuildDesired([]Candidate{
		candidate("11.22.0.0/16", KindRange, 1, "range-feed", 0),
		candidate("11.22.33.44/32", KindIP, 2, "host-feed", 1),
	}, nil)
	host := objectByPrefix(t, objects, "11.22.33.44/32")
	if host.Desired || host.Suppression != SuppressedCovered || host.CoveredBy == nil {
		t.Fatal("covered host was not suppressed")
	}
	if summary.CoveredHosts != 1 {
		t.Fatal("covered-host summary incorrect")
	}
	if !objectByPrefix(t, objects, "11.22.0.0/16").Desired {
		t.Fatal("covering range was unexpectedly suppressed")
	}
}

func TestOverlappingAndAdjacentRangesAreNotMergedOrSuppressed(t *testing.T) {
	objects, _ := BuildDesired([]Candidate{
		candidate("11.23.0.0/16", KindRange, 1, "feed-one", 0),
		candidate("11.23.1.0/24", KindRange, 1, "feed-one", 0),
		candidate("11.24.0.0/24", KindRange, 1, "feed-one", 0),
		candidate("11.24.1.0/24", KindRange, 1, "feed-one", 0),
	}, nil)
	if len(objects) != 4 {
		t.Fatal("overlapping or adjacent ranges were merged")
	}
	for _, object := range objects {
		if !object.Desired || object.Suppression != SuppressedNone {
			t.Fatal("range overlap incorrectly suppressed")
		}
	}
}

func TestAllowlistAnyOverlapTakesPrecedence(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("12.34.56.64/26")}
	objects, summary := BuildDesired([]Candidate{
		candidate("12.34.56.0/24", KindRange, 1, "feed-one", 0),
		candidate("12.34.57.1/32", KindIP, 1, "feed-one", 0),
	}, allow)
	blocked := objectByPrefix(t, objects, "12.34.56.0/24")
	if blocked.Desired || blocked.Suppression != SuppressedAllowlist {
		t.Fatal("overlapping allowlist did not suppress imported range")
	}
	if !objectByPrefix(t, objects, "12.34.57.1/32").Desired || summary.Allowlisted != 1 {
		t.Fatal("allowlist suppression escaped its overlap")
	}
}

func TestPrimaryContributorIsDeterministic(t *testing.T) {
	objects, _ := BuildDesired([]Candidate{
		candidate("13.45.67.0/24", KindRange, 9, "feed-z", 3),
		candidate("13.45.67.0/24", KindRange, 2, "feed-a", 1),
		candidate("13.45.67.0/24", KindRange, 1, "feed-b", 1),
	}, nil)
	if objects[0].Primary.FeedName != "feed-a" {
		t.Fatal("primary contributor selection is not deterministic")
	}
}

func TestUnsafeCandidatesAreRejectedDefensively(t *testing.T) {
	objects, summary := BuildDesired([]Candidate{
		candidate("10.0.0.0/8", KindRange, 1, "feed-one", 0),
		candidate("14.0.0.0/8", KindRange, 1, "feed-one", 0),
	}, nil)
	if len(objects) != 1 || summary.RejectedSafety != 1 {
		t.Fatal("unsafe candidate was not rejected")
	}
}

func TestOutputOrderingIsStable(t *testing.T) {
	input := []Candidate{
		candidate("15.2.0.0/16", KindRange, 1, "feed-one", 0),
		candidate("15.1.0.0/16", KindRange, 1, "feed-one", 0),
	}
	first, _ := BuildDesired(input, nil)
	second, _ := BuildDesired([]Candidate{input[1], input[0]}, nil)
	if len(first) != len(second) {
		t.Fatal("stable output changed length")
	}
	for i := range first {
		if first[i].Prefix != second[i].Prefix {
			t.Fatal("output order depends on input order")
		}
	}
}
