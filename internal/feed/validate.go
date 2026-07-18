package feed

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/netip"
	"slices"
	"strconv"

	"crowdshield/internal/network"
)

type entryKey struct {
	prefix netip.Prefix
	kind   network.Kind
}

func compareEntry(a, b Entry) int {
	if a.Prefix.Addr().Is4() != b.Prefix.Addr().Is4() {
		if a.Prefix.Addr().Is4() {
			return -1
		}
		return 1
	}
	if value := a.Prefix.Addr().Compare(b.Prefix.Addr()); value != 0 {
		return value
	}
	if value := cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()); value != 0 {
		return value
	}
	return cmp.Compare(a.Kind, b.Kind)
}

func validValidationPolicy(policy ValidationPolicy) bool {
	return policy.ExpectedMinEntries >= 1 && policy.ExpectedMaxEntries >= policy.ExpectedMinEntries &&
		policy.PreviousAcceptedEntries >= 0 && policy.MaxGrowthRatio >= 1 && policy.MaxGrowthRatio <= 100 &&
		policy.MaxShrinkRatio > 0 && policy.MaxShrinkRatio <= 1 &&
		!math.IsNaN(policy.MaxGrowthRatio) && !math.IsNaN(policy.MaxShrinkRatio) &&
		!math.IsInf(policy.MaxGrowthRatio, 0) && !math.IsInf(policy.MaxShrinkRatio, 0) &&
		!policy.Now.IsZero() && policy.MaxMetadataAge >= 0 && policy.MaxFutureSkew >= 0
}

func snapshotVersion(entries []Entry) string {
	hash := sha256.New()
	for _, entry := range entries {
		_, _ = hash.Write([]byte(strconv.Itoa(int(entry.Kind))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(entry.Prefix.String()))
		_, _ = hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Validate applies safety filtering, exact in-feed deduplication, absolute
// count bounds, change-ratio checks, and metadata freshness.
func Validate(result Result, policy ValidationPolicy) (Snapshot, error) {
	if !validValidationPolicy(policy) {
		return Snapshot{}, feedError(ErrPolicy, nil)
	}
	if !result.Metadata.GeneratedAt.IsZero() {
		if result.Metadata.GeneratedAt.After(policy.Now.Add(policy.MaxFutureSkew)) ||
			(policy.MaxMetadataAge > 0 && result.Metadata.GeneratedAt.Before(policy.Now.Add(-policy.MaxMetadataAge))) {
			return Snapshot{}, feedError(ErrMetadata, nil)
		}
	}

	snapshot := Snapshot{RawEntries: len(result.Entries), Metadata: result.Metadata}
	seen := make(map[entryKey]struct{}, len(result.Entries))
	for _, entry := range result.Entries {
		prefix := entry.Prefix.Masked()
		safe, _ := network.IsSafePrefix(prefix)
		if !safe || network.ValidateKind(prefix, entry.Kind) != nil {
			snapshot.RejectedSafety++
			continue
		}
		key := entryKey{prefix: prefix, kind: entry.Kind}
		if _, exists := seen[key]; exists {
			snapshot.Duplicates++
			continue
		}
		seen[key] = struct{}{}
		snapshot.Entries = append(snapshot.Entries, Entry{Prefix: prefix, Kind: entry.Kind})
	}
	slices.SortFunc(snapshot.Entries, compareEntry)
	count := len(snapshot.Entries)
	if count < policy.ExpectedMinEntries || count > policy.ExpectedMaxEntries {
		return Snapshot{}, feedError(ErrEntryCount, nil)
	}
	if policy.PreviousAcceptedEntries > 0 {
		ratio := float64(count) / float64(policy.PreviousAcceptedEntries)
		if ratio > policy.MaxGrowthRatio || ratio < policy.MaxShrinkRatio {
			return Snapshot{}, feedError(ErrSuspiciousChange, nil)
		}
	}
	snapshot.Version = snapshotVersion(snapshot.Entries)
	return snapshot, nil
}
