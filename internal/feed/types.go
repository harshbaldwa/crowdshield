package feed

import (
	"net/netip"
	"time"

	"crowdshield/internal/network"
)

type Format string

const (
	FormatSpamhausDROPJSONL Format = "spamhaus-drop-jsonl"
	FormatFireHOLNetset     Format = "firehol-netset"
	FormatPlain             Format = "plain"
)

type Family string

const (
	FamilyAny  Family = "any"
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

type Limits struct {
	Family              Family
	MaxLineBytes        int
	MaxMalformedLines   int
	MaxMalformedRatio   float64
	RequireFinalNewline bool
}

type Entry struct {
	Prefix netip.Prefix
	Kind   network.Kind
}

type Metadata struct {
	GeneratedAt     time.Time
	DeclaredRecords int
	Copyright       string
	TermsURL        string
}

type Result struct {
	Entries      []Entry
	TotalRecords int
	Malformed    int
	Metadata     Metadata
}

type ValidationPolicy struct {
	ExpectedMinEntries      int
	ExpectedMaxEntries      int
	MaxGrowthRatio          float64
	MaxShrinkRatio          float64
	PreviousAcceptedEntries int
	Now                     time.Time
	MaxMetadataAge          time.Duration
	MaxFutureSkew           time.Duration
}

type Snapshot struct {
	Entries        []Entry
	Version        string
	RawEntries     int
	RejectedSafety int
	Duplicates     int
	Metadata       Metadata
}
