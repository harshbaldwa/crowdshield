package feed

import (
	"os"
	"path/filepath"
	"testing"

	"crowdshield/internal/network"
)

func openFixture(t *testing.T, name string) *os.File {
	t.Helper()
	// #nosec G304 -- test fixtures are constrained to the repository testdata directory and static test names.
	file, err := os.Open(filepath.Join("..", "..", "testdata", "feeds", name))
	if err != nil {
		t.Fatal("unable to open feed fixture")
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func defaultLimits(family Family) Limits {
	return Limits{
		Family:              family,
		MaxLineBytes:        64 << 10,
		MaxMalformedLines:   10,
		MaxMalformedRatio:   0.5,
		RequireFinalNewline: true,
	}
}

func TestSpamhausJSONLParser(t *testing.T) {
	result, err := Parse(FormatSpamhausDROPJSONL, openFixture(t, "spamhaus-valid.jsonl"), defaultLimits(FamilyIPv4))
	if err != nil {
		t.Fatal("valid Spamhaus fixture rejected")
	}
	if result.TotalRecords != 3 || len(result.Entries) != 3 || result.Malformed != 0 {
		t.Fatal("unexpected Spamhaus parse counts")
	}
	if result.Metadata.DeclaredRecords != 3 || result.Metadata.GeneratedAt.IsZero() || result.Metadata.TermsURL == "" {
		t.Fatal("Spamhaus metadata not validated")
	}
	for _, entry := range result.Entries {
		if entry.Kind != network.KindRange || !entry.Prefix.Addr().Is4() {
			t.Fatal("Spamhaus entry kind or family changed")
		}
	}
}

func TestFireHOLNetsetParser(t *testing.T) {
	result, err := Parse(FormatFireHOLNetset, openFixture(t, "firehol-valid.netset"), defaultLimits(FamilyIPv4))
	if err != nil {
		t.Fatal("valid FireHOL fixture rejected")
	}
	if result.TotalRecords != 3 || len(result.Entries) != 3 || result.Malformed != 0 {
		t.Fatal("comments or blank lines were treated as records")
	}
	if result.Entries[1].Kind != network.KindIP {
		t.Fatal("bare address did not preserve IP scope")
	}
}

func TestPlainParserSupportsIPv6(t *testing.T) {
	body := "2606:4700:4700::/48\n2620:fe::9\n"
	result, err := Parse(FormatPlain, stringsReader(body), defaultLimits(FamilyIPv6))
	if err != nil || len(result.Entries) != 2 || result.Entries[1].Kind != network.KindIP {
		t.Fatal("valid IPv6 plain feed rejected")
	}
}

func TestParserAllowsBoundedMalformedEntries(t *testing.T) {
	limits := defaultLimits(FamilyIPv4)
	limits.MaxMalformedLines = 1
	limits.MaxMalformedRatio = 0.5
	body := "8.8.8.0/24\nnot-an-indicator\n9.9.9.0/24\n"
	result, err := Parse(FormatPlain, stringsReader(body), limits)
	if err != nil || result.Malformed != 1 || len(result.Entries) != 2 {
		t.Fatal("bounded malformed entry was not handled")
	}
}

func TestParserRejectsMalformedThreshold(t *testing.T) {
	limits := defaultLimits(FamilyIPv4)
	limits.MaxMalformedLines = 0
	body := "8.8.8.0/24\nnot-an-indicator\n"
	_, err := Parse(FormatPlain, stringsReader(body), limits)
	if err == nil || !IsCategory(err, ErrMalformedThreshold) {
		t.Fatal("malformed threshold was not enforced")
	}
}

func TestParserRejectsWrongFamily(t *testing.T) {
	limits := defaultLimits(FamilyIPv4)
	limits.MaxMalformedLines = 0
	_, err := Parse(FormatPlain, stringsReader("2606:4700:4700::/48\n"), limits)
	if err == nil || !IsCategory(err, ErrMalformedThreshold) {
		t.Fatal("family mismatch was not rejected")
	}
}

func TestParserRejectsOverlongLine(t *testing.T) {
	limits := defaultLimits(FamilyIPv4)
	limits.MaxLineBytes = 16
	_, err := Parse(FormatPlain, stringsReader("12345678901234567890\n"), limits)
	if err == nil || !IsCategory(err, ErrLineTooLong) {
		t.Fatal("overlong line was not rejected")
	}
}

func TestParserRejectsMissingFinalNewline(t *testing.T) {
	_, err := Parse(FormatPlain, stringsReader("8.8.8.0/24"), defaultLimits(FamilyIPv4))
	if err == nil || !IsCategory(err, ErrTruncated) {
		t.Fatal("missing final newline was not rejected")
	}
}

func TestSpamhausRejectsMetadataRecordMismatch(t *testing.T) {
	body := "{\"cidr\":\"8.8.8.0/24\"}\n" +
		"{\"type\":\"metadata\",\"timestamp\":1784246400,\"copyright\":\"copyright\",\"terms\":\"https://example.invalid/terms\",\"records\":2}\n"

	_, err := Parse(
		FormatSpamhausDROPJSONL,
		stringsReader(body),
		defaultLimits(FamilyIPv4),
	)
	if err == nil || !IsCategory(err, ErrMetadata) {
		t.Fatal("metadata record mismatch accepted")
	}
}

func TestSpamhausRejectsMissingMetadata(t *testing.T) {
	body := "{\"cidr\":\"8.8.8.0/24\"}\n"

	_, err := Parse(
		FormatSpamhausDROPJSONL,
		stringsReader(body),
		defaultLimits(FamilyIPv4),
	)
	if err == nil || !IsCategory(err, ErrMetadata) {
		t.Fatal("Spamhaus feed without metadata accepted")
	}
}

func TestSpamhausRejectsDuplicateMetadata(t *testing.T) {
	body := "{\"cidr\":\"8.8.8.0/24\"}\n" +
		"{\"type\":\"metadata\",\"timestamp\":1784246400,\"copyright\":\"copyright\",\"terms\":\"https://example.invalid/terms\",\"records\":1}\n" +
		"{\"type\":\"metadata\",\"timestamp\":1784246400,\"copyright\":\"copyright\",\"terms\":\"https://example.invalid/terms\",\"records\":1}\n"

	_, err := Parse(
		FormatSpamhausDROPJSONL,
		stringsReader(body),
		defaultLimits(FamilyIPv4),
	)
	if err == nil || !IsCategory(err, ErrMetadata) {
		t.Fatal("duplicate Spamhaus metadata accepted")
	}
}

func TestSpamhausRejectsRecordAfterMetadata(t *testing.T) {
	body := "{\"type\":\"metadata\",\"timestamp\":1784246400,\"copyright\":\"copyright\",\"terms\":\"https://example.invalid/terms\",\"records\":1}\n" +
		"{\"cidr\":\"8.8.8.0/24\"}\n"

	_, err := Parse(
		FormatSpamhausDROPJSONL,
		stringsReader(body),
		defaultLimits(FamilyIPv4),
	)
	if err == nil || !IsCategory(err, ErrMetadata) {
		t.Fatal("Spamhaus record after terminal metadata accepted")
	}
}

func TestSpamhausAllowsBoundedMalformedRecordBeforeMetadata(t *testing.T) {
	limits := defaultLimits(FamilyIPv4)
	limits.MaxMalformedLines = 1
	limits.MaxMalformedRatio = 0.5

	body := "{\"cidr\":\"8.8.8.0/24\"}\n" +
		"{\"cidr\":\"not-a-prefix\"}\n" +
		"{\"type\":\"metadata\",\"timestamp\":1784246400,\"copyright\":\"copyright\",\"terms\":\"https://example.invalid/terms\",\"records\":2}\n"

	result, err := Parse(
		FormatSpamhausDROPJSONL,
		stringsReader(body),
		limits,
	)
	if err != nil {
		t.Fatal("bounded malformed Spamhaus record rejected")
	}
	if result.TotalRecords != 2 ||
		result.Malformed != 1 ||
		len(result.Entries) != 1 {
		t.Fatal("unexpected malformed Spamhaus record counts")
	}
}

func TestParserRejectsUnknownFormat(t *testing.T) {
	_, err := Parse(Format("unknown"), stringsReader(""), defaultLimits(FamilyIPv4))
	if err == nil || !IsCategory(err, ErrFormat) {
		t.Fatal("unknown parser format accepted")
	}
}
