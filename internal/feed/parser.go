package feed

import (
	"bufio"
	"encoding/json"
	"io"
	"math"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"crowdshield/internal/network"
)

type trackingReader struct {
	reader io.Reader
	last   byte
	read   int64
}

func (r *trackingReader) Read(body []byte) (int, error) {
	count, err := r.reader.Read(body)
	if count > 0 {
		r.last = body[count-1]
		r.read += int64(count)
	}
	return count, err
}

func validLimits(limits Limits) bool {
	return (limits.Family == FamilyAny || limits.Family == FamilyIPv4 || limits.Family == FamilyIPv6) &&
		limits.MaxLineBytes > 0 && limits.MaxMalformedLines >= 0 &&
		!math.IsNaN(limits.MaxMalformedRatio) && limits.MaxMalformedRatio >= 0 && limits.MaxMalformedRatio <= 1
}

func familyMatches(prefixIs4 bool, family Family) bool {
	return family == FamilyAny || (family == FamilyIPv4 && prefixIs4) || (family == FamilyIPv6 && !prefixIs4)
}

func malformedAllowed(result Result, limits Limits) bool {
	if result.Malformed > limits.MaxMalformedLines {
		return false
	}
	if result.TotalRecords == 0 {
		return result.Malformed == 0
	}
	return float64(result.Malformed)/float64(result.TotalRecords) <= limits.MaxMalformedRatio
}

func scan(reader io.Reader, limits Limits, consume func(string, int) error) (*trackingReader, error) {
	tracked := &trackingReader{reader: reader}
	scanner := bufio.NewScanner(tracked)
	initial := limits.MaxLineBytes
	if initial > 4096 {
		initial = 4096
	}
	scanner.Buffer(make([]byte, initial), limits.MaxLineBytes)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if line == 1 {
			text = strings.TrimPrefix(text, "\ufeff")
		}
		if !utf8.ValidString(text) {
			return tracked, feedError(ErrFormat, nil)
		}
		if err := consume(text, line); err != nil {
			return tracked, err
		}
	}
	if scanner.Err() != nil {
		return tracked, feedError(ErrLineTooLong, scanner.Err())
	}
	if tracked.read == 0 {
		return tracked, feedError(ErrEmpty, nil)
	}
	if limits.RequireFinalNewline && tracked.last != '\n' {
		return tracked, feedError(ErrTruncated, nil)
	}
	return tracked, nil
}

type spamhausMetadata struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
	Copyright string `json:"copyright"`
	Terms     string `json:"terms"`
	Records   int    `json:"records"`
}

type spamhausRecord struct {
	CIDR string `json:"cidr"`
}

func parseSpamhaus(reader io.Reader, limits Limits) (Result, error) {
	var result Result
	metadataSeen := false
	_, err := scan(reader, limits, func(line string, _ int) error {
		line = strings.TrimSpace(line)
		if line == "" {
			return nil
		}
		if !metadataSeen {
			var metadata spamhausMetadata
			if err := json.Unmarshal([]byte(line), &metadata); err != nil {
				return feedError(ErrMetadata, err)
			}
			terms, err := url.Parse(metadata.Terms)
			if err != nil || terms.Scheme != "https" || terms.Hostname() == "" || metadata.Type != "metadata" || metadata.Timestamp <= 0 || metadata.Records < 1 || strings.TrimSpace(metadata.Copyright) == "" || len(metadata.Copyright) > 2048 || len(metadata.Terms) > 2048 {
				return feedError(ErrMetadata, err)
			}
			result.Metadata = Metadata{
				GeneratedAt:     time.Unix(metadata.Timestamp, 0).UTC(),
				DeclaredRecords: metadata.Records,
				Copyright:       metadata.Copyright,
				TermsURL:        metadata.Terms,
			}
			metadataSeen = true
			return nil
		}

		result.TotalRecords++
		var record spamhausRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			result.Malformed++
			return nil
		}
		prefix, err := network.NormalizePrefix(record.CIDR)
		if err != nil || !familyMatches(prefix.Addr().Is4(), limits.Family) {
			result.Malformed++
			return nil
		}
		result.Entries = append(result.Entries, Entry{Prefix: prefix, Kind: network.KindRange})
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if !metadataSeen || result.Metadata.DeclaredRecords != result.TotalRecords {
		return Result{}, feedError(ErrMetadata, nil)
	}
	if !malformedAllowed(result, limits) {
		return Result{}, feedError(ErrMalformedThreshold, nil)
	}
	return result, nil
}

func stripComment(line string) string {
	cut := len(line)
	if index := strings.IndexByte(line, '#'); index >= 0 && index < cut {
		cut = index
	}
	if index := strings.IndexByte(line, ';'); index >= 0 && index < cut {
		cut = index
	}
	return strings.TrimSpace(line[:cut])
}

func parseNetset(reader io.Reader, limits Limits) (Result, error) {
	var result Result
	_, err := scan(reader, limits, func(line string, _ int) error {
		line = stripComment(line)
		if line == "" {
			return nil
		}
		result.TotalRecords++
		fields := strings.Fields(line)
		if len(fields) != 1 {
			result.Malformed++
			return nil
		}
		prefix, kind, err := network.ParseValue(fields[0])
		if err != nil || !familyMatches(prefix.Addr().Is4(), limits.Family) {
			result.Malformed++
			return nil
		}
		result.Entries = append(result.Entries, Entry{Prefix: prefix, Kind: kind})
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if result.TotalRecords == 0 {
		return Result{}, feedError(ErrEmpty, nil)
	}
	if !malformedAllowed(result, limits) {
		return Result{}, feedError(ErrMalformedThreshold, nil)
	}
	return result, nil
}

// Parse handles one configured feed format with bounded line and malformed-input limits.
func Parse(format Format, reader io.Reader, limits Limits) (Result, error) {
	if !validLimits(limits) {
		return Result{}, feedError(ErrPolicy, nil)
	}
	switch format {
	case FormatSpamhausDROPJSONL:
		return parseSpamhaus(reader, limits)
	case FormatFireHOLNetset, FormatPlain:
		return parseNetset(reader, limits)
	default:
		return Result{}, feedError(ErrFormat, nil)
	}
}
