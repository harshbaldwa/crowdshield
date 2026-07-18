package network

import (
	"cmp"
	"net/netip"
	"slices"
)

type Scope string

const (
	ScopeIP    Scope = "Ip"
	ScopeRange Scope = "Range"
)

type Suppression string

const (
	SuppressedNone      Suppression = ""
	SuppressedAllowlist Suppression = "allowlist"
	SuppressedCovered   Suppression = "covered_by_range"
)

type Candidate struct {
	Prefix    netip.Prefix
	Kind      Kind
	FeedID    int64
	FeedName  string
	FeedOrder int
}

type Contributor struct {
	FeedID    int64
	FeedName  string
	FeedOrder int
	Kind      Kind
}

type Object struct {
	Prefix       netip.Prefix
	Scope        Scope
	Contributors []Contributor
	Primary      Contributor
	Desired      bool
	Suppression  Suppression
	CoveredBy    *netip.Prefix
}

type Summary struct {
	Input           int
	Objects         int
	Desired         int
	ExactDuplicates int
	RejectedSafety  int
	Allowlisted     int
	CoveredHosts    int
}

type contributorKey struct {
	feedID int64
	name   string
	kind   Kind
}

type objectBuilder struct {
	prefix       netip.Prefix
	contributors []Contributor
	seen         map[contributorKey]struct{}
}

func compareContributor(a, b Contributor) int {
	if value := cmp.Compare(a.FeedOrder, b.FeedOrder); value != 0 {
		return value
	}
	if value := cmp.Compare(a.FeedName, b.FeedName); value != 0 {
		return value
	}
	if value := cmp.Compare(a.FeedID, b.FeedID); value != 0 {
		return value
	}
	return cmp.Compare(a.Kind, b.Kind)
}

func compareObject(a, b Object) int {
	if a.Prefix.Addr().Is4() != b.Prefix.Addr().Is4() {
		if a.Prefix.Addr().Is4() {
			return -1
		}
		return 1
	}
	if value := a.Prefix.Addr().Compare(b.Prefix.Addr()); value != 0 {
		return value
	}
	return cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits())
}

func overlapsAllowlist(prefix netip.Prefix, allowlist []netip.Prefix) bool {
	for _, allowed := range allowlist {
		if allowed.IsValid() && prefix.Overlaps(allowed.Masked()) {
			return true
		}
	}
	return false
}

// BuildDesired converts validated feed candidates into deterministic
// enforcement objects. It never expands or merges CIDRs.
func BuildDesired(candidates []Candidate, allowlist []netip.Prefix) ([]Object, Summary) {
	summary := Summary{Input: len(candidates)}
	builders := make(map[netip.Prefix]*objectBuilder, len(candidates))
	for _, candidate := range candidates {
		prefix := candidate.Prefix.Masked()
		safe, _ := IsSafePrefix(prefix)
		if !safe || ValidateKind(prefix, candidate.Kind) != nil || candidate.FeedID < 1 || candidate.FeedName == "" {
			summary.RejectedSafety++
			continue
		}
		builder, exists := builders[prefix]
		if !exists {
			builder = &objectBuilder{prefix: prefix, seen: make(map[contributorKey]struct{})}
			builders[prefix] = builder
		} else {
			summary.ExactDuplicates++
		}
		key := contributorKey{feedID: candidate.FeedID, name: candidate.FeedName, kind: candidate.Kind}
		if _, exists := builder.seen[key]; exists {
			continue
		}
		builder.seen[key] = struct{}{}
		builder.contributors = append(builder.contributors, Contributor{
			FeedID: candidate.FeedID, FeedName: candidate.FeedName, FeedOrder: candidate.FeedOrder, Kind: candidate.Kind,
		})
	}

	objects := make([]Object, 0, len(builders))
	for _, builder := range builders {
		slices.SortFunc(builder.contributors, compareContributor)
		scope := ScopeRange
		for _, contributor := range builder.contributors {
			if contributor.Kind == KindIP {
				scope = ScopeIP
				break
			}
		}
		object := Object{
			Prefix:       builder.prefix,
			Scope:        scope,
			Contributors: slices.Clone(builder.contributors),
			Primary:      builder.contributors[0],
			Desired:      true,
		}
		if overlapsAllowlist(object.Prefix, allowlist) {
			object.Desired = false
			object.Suppression = SuppressedAllowlist
			summary.Allowlisted++
		}
		objects = append(objects, object)
	}
	slices.SortFunc(objects, compareObject)

	for i := range objects {
		if !objects[i].Desired || objects[i].Scope != ScopeIP {
			continue
		}
		var covering *netip.Prefix
		for j := range objects {
			if i == j || !objects[j].Desired || objects[j].Scope != ScopeRange {
				continue
			}
			if objects[j].Prefix.Bits() >= objects[i].Prefix.Addr().BitLen() || !objects[j].Prefix.Contains(objects[i].Prefix.Addr()) {
				continue
			}
			if covering == nil || objects[j].Prefix.Bits() > covering.Bits() || (objects[j].Prefix.Bits() == covering.Bits() && objects[j].Prefix.Addr().Compare(covering.Addr()) < 0) {
				value := objects[j].Prefix
				covering = &value
			}
		}
		if covering != nil {
			objects[i].Desired = false
			objects[i].Suppression = SuppressedCovered
			objects[i].CoveredBy = covering
			summary.CoveredHosts++
		}
	}

	summary.Objects = len(objects)
	for _, object := range objects {
		if object.Desired {
			summary.Desired++
		}
	}
	return objects, summary
}
