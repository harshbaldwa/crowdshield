package feed

import (
	"testing"
	"time"

	"crowdshield/internal/network"
)

func mustEntry(raw string, kind network.Kind) Entry {
	prefix, err := network.NormalizePrefix(raw)
	if err != nil {
		panic("invalid static entry")
	}
	return Entry{Prefix: prefix, Kind: kind}
}

func validationPolicy(now time.Time) ValidationPolicy {
	return ValidationPolicy{
		ExpectedMinEntries: 1,
		ExpectedMaxEntries: 100,
		MaxGrowthRatio:     2,
		MaxShrinkRatio:     0.5,
		Now:                now,
		MaxMetadataAge:     72 * time.Hour,
		MaxFutureSkew:      5 * time.Minute,
	}
}

func TestValidateFiltersUnsafeAndDeduplicates(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	result := Result{Entries: []Entry{
		mustEntry("8.8.8.0/24", network.KindRange),
		mustEntry("8.8.8.0/24", network.KindRange),
		mustEntry("9.9.9.9/32", network.KindIP),
		mustEntry("10.0.0.0/8", network.KindRange),
		mustEntry("192.0.2.0/24", network.KindRange),
	}}
	policy := validationPolicy(now)
	policy.ExpectedMinEntries = 2
	policy.PreviousAcceptedEntries = 2
	snapshot, err := Validate(result, policy)
	if err != nil {
		t.Fatal("valid filtered snapshot rejected")
	}
	if len(snapshot.Entries) != 2 || snapshot.RejectedSafety != 2 || snapshot.Duplicates != 1 {
		t.Fatal("safety filtering or exact deduplication failed")
	}
	if snapshot.Version == "" {
		t.Fatal("snapshot version missing")
	}
}

func TestValidateRejectsAbsoluteCountBounds(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	result := Result{Entries: []Entry{mustEntry("8.8.8.0/24", network.KindRange)}}
	policy := validationPolicy(now)
	policy.ExpectedMinEntries = 2
	_, err := Validate(result, policy)
	if err == nil || !IsCategory(err, ErrEntryCount) {
		t.Fatal("small snapshot accepted")
	}
}

func TestValidateRejectsGrowthAndShrink(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		mustEntry("8.8.8.0/24", network.KindRange),
		mustEntry("9.9.9.0/24", network.KindRange),
		mustEntry("11.22.0.0/16", network.KindRange),
	}
	growth := validationPolicy(now)
	growth.PreviousAcceptedEntries = 1
	growth.MaxGrowthRatio = 2
	if _, err := Validate(Result{Entries: entries}, growth); err == nil || !IsCategory(err, ErrSuspiciousChange) {
		t.Fatal("suspicious growth accepted")
	}

	shrink := validationPolicy(now)
	shrink.PreviousAcceptedEntries = 10
	shrink.MaxShrinkRatio = 0.5
	if _, err := Validate(Result{Entries: entries}, shrink); err == nil || !IsCategory(err, ErrSuspiciousChange) {
		t.Fatal("suspicious shrink accepted")
	}
}

func TestValidateChecksMetadataTime(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	result := Result{
		Entries:  []Entry{mustEntry("8.8.8.0/24", network.KindRange)},
		Metadata: Metadata{GeneratedAt: now.Add(-73 * time.Hour)},
	}
	if _, err := Validate(result, validationPolicy(now)); err == nil || !IsCategory(err, ErrMetadata) {
		t.Fatal("stale metadata accepted")
	}
	result.Metadata.GeneratedAt = now.Add(6 * time.Minute)
	if _, err := Validate(result, validationPolicy(now)); err == nil || !IsCategory(err, ErrMetadata) {
		t.Fatal("future metadata accepted")
	}
}

func TestSnapshotVersionIsOrderIndependent(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	a := mustEntry("8.8.8.0/24", network.KindRange)
	b := mustEntry("9.9.9.9/32", network.KindIP)
	first, err := Validate(Result{Entries: []Entry{a, b}}, validationPolicy(now))
	if err != nil {
		t.Fatal("first snapshot failed")
	}
	second, err := Validate(Result{Entries: []Entry{b, a}}, validationPolicy(now))
	if err != nil {
		t.Fatal("second snapshot failed")
	}
	if first.Version != second.Version {
		t.Fatal("snapshot version depends on feed ordering")
	}
}

func TestValidateRejectsInvalidPolicy(t *testing.T) {
	policy := validationPolicy(time.Now())
	policy.MaxShrinkRatio = 2
	_, err := Validate(Result{}, policy)
	if err == nil || !IsCategory(err, ErrPolicy) {
		t.Fatal("invalid validation policy accepted")
	}
}
