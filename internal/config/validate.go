package config

import (
	"math"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	feedNamePattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	topicPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	hostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

func positiveDuration(d Duration) bool { return d.Duration() > 0 }

func validateRetry(field string, retry RetryConfig) error {
	if retry.MaxAttempts < 1 || retry.MaxAttempts > 10 {
		return configError(ErrValidation, field+".max_attempts", nil)
	}
	if !positiveDuration(retry.InitialBackoff) || !positiveDuration(retry.MaxBackoff) ||
		retry.InitialBackoff > retry.MaxBackoff || retry.MaxBackoff.Duration() > 24*time.Hour {
		return configError(ErrDuration, field+".backoff", nil)
	}
	return nil
}

func validateListenAddress(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || portText == "" {
		return configError(ErrServer, "server.listen_address", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return configError(ErrServer, "server.listen_address", err)
	}
	if strings.ContainsAny(host, "\r\n\x00") {
		return configError(ErrServer, "server.listen_address", nil)
	}
	return nil
}

func unsafeLiteralHost(host string) bool {
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(lower)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified()
}

func validateRemoteURL(field, raw string, allowHTTP, globalHTTP bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" {
		return configError(ErrFeedURL, field, err)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return configError(ErrFeedURL, field, nil)
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !allowHTTP || !globalHTTP {
			return configError(ErrFeedURL, field, nil)
		}
	}
	if unsafeLiteralHost(parsed.Hostname()) {
		return configError(ErrFeedURL, field, nil)
	}
	if strings.ContainsAny(parsed.Host, "\r\n\x00") {
		return configError(ErrFeedURL, field, nil)
	}
	return nil
}

func canonicalHTTPHosts(values []string) ([]string, error) {
	if len(values) > 16 {
		return nil, configError(ErrValidation, "crowdsec.allowed_http_hosts", nil)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00/\\@?#") {
			return nil, configError(ErrValidation, "crowdsec.allowed_http_hosts", nil)
		}
		host := strings.ToLower(strings.TrimSuffix(value, "."))
		if host == "" || len(host) > 253 {
			return nil, configError(ErrValidation, "crowdsec.allowed_http_hosts", nil)
		}
		if address, err := netip.ParseAddr(host); err == nil {
			host = address.Unmap().String()
		} else {
			for _, label := range strings.Split(host, ".") {
				if !hostLabelPattern.MatchString(label) {
					return nil, configError(ErrValidation, "crowdsec.allowed_http_hosts", nil)
				}
			}
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		result = append(result, host)
	}
	slices.Sort(result)
	return result, nil
}

func validateFeed(cfg Config, index int, feed FeedConfig) error {
	field := "feeds"
	if len(feed.Name) == 0 || len(feed.Name) > cfg.Validation.MaxFeedNameLength || !feedNamePattern.MatchString(feed.Name) {
		return indexedError(ErrFeedName, field, index, nil)
	}
	if err := validateRemoteURL("feeds.url", feed.URL, feed.AllowHTTP, cfg.Validation.AllowHTTP); err != nil {
		return indexedError(ErrFeedURL, field, index, err)
	}
	if feed.Format != "spamhaus-drop-jsonl" && feed.Format != "firehol-netset" && feed.Format != "plain" {
		return indexedError(ErrValidation, field, index, nil)
	}
	if feed.Family != "ipv4" && feed.Family != "ipv6" && feed.Family != "any" {
		return indexedError(ErrValidation, field, index, nil)
	}
	if !positiveDuration(feed.Timeout) || feed.Timeout.Duration() > 10*time.Minute || !positiveDuration(feed.MinUpdateInterval) {
		return indexedError(ErrDuration, field, index, nil)
	}
	if feed.MaxDownloadBytes < 1 || feed.MaxDownloadBytes > 64<<20 {
		return indexedError(ErrFeedThreshold, field, index, nil)
	}
	if feed.ExpectedMinEntries < 1 || feed.ExpectedMaxEntries < feed.ExpectedMinEntries || feed.ExpectedMaxEntries > 10_000_000 {
		return indexedError(ErrFeedThreshold, field, index, nil)
	}
	if math.IsNaN(feed.MaxGrowthRatio) || math.IsInf(feed.MaxGrowthRatio, 0) || feed.MaxGrowthRatio < 1 || feed.MaxGrowthRatio > 100 {
		return indexedError(ErrFeedThreshold, field, index, nil)
	}
	if math.IsNaN(feed.MaxShrinkRatio) || math.IsInf(feed.MaxShrinkRatio, 0) || feed.MaxShrinkRatio <= 0 || feed.MaxShrinkRatio > 1 {
		return indexedError(ErrFeedThreshold, field, index, nil)
	}
	if feed.MaxMalformedLines < 0 || math.IsNaN(feed.MaxMalformedRatio) || math.IsInf(feed.MaxMalformedRatio, 0) ||
		feed.MaxMalformedRatio < 0 || feed.MaxMalformedRatio > 1 {
		return indexedError(ErrFeedThreshold, field, index, nil)
	}
	if strings.TrimSpace(feed.Attribution) == "" || len(feed.Attribution) > 2048 || strings.ContainsAny(feed.Attribution, "\r\n\x00") {
		return indexedError(ErrValidation, field, index, nil)
	}
	if len(feed.ContentTypes) == 0 {
		return indexedError(ErrValidation, field, index, nil)
	}
	for _, contentType := range feed.ContentTypes {
		if strings.TrimSpace(contentType) == "" || strings.ContainsAny(contentType, "\r\n\x00") {
			return indexedError(ErrValidation, field, index, nil)
		}
	}
	return nil
}

// Validate checks all cross-field safety constraints and canonicalizes allowlists.
func (c *Config) Validate() error {
	if err := validateListenAddress(c.Server.ListenAddress); err != nil {
		return err
	}
	for _, item := range []struct {
		field string
		value Duration
	}{
		{"server.read_header_timeout", c.Server.ReadHeaderTimeout},
		{"server.read_timeout", c.Server.ReadTimeout},
		{"server.write_timeout", c.Server.WriteTimeout},
		{"server.idle_timeout", c.Server.IdleTimeout},
		{"server.shutdown_timeout", c.Server.ShutdownTimeout},
		{"server.lapi_unreachable_grace", c.Server.LAPIUnreachableGrace},
		{"server.readiness_max_sync_age", c.Server.ReadinessMaxSyncAge},
		{"schedule.interval", c.Schedule.Interval},
		{"database.busy_timeout", c.Database.BusyTimeout},
		{"database.history_retention", c.Database.HistoryRetention},
		{"crowdsec.request_timeout", c.CrowdSec.RequestTimeout},
		{"crowdsec.connect_timeout", c.CrowdSec.ConnectTimeout},
		{"crowdsec.auth_refresh_before", c.CrowdSec.AuthRefreshBefore},
		{"decisions.duration", c.Decisions.Duration},
		{"decisions.refresh_before", c.Decisions.RefreshBefore},
		{"validation.dns_lookup_timeout", c.Validation.DNSLookupTimeout},
		{"notifications.request_timeout", c.Notifications.RequestTimeout},
		{"notifications.cooldown", c.Notifications.Cooldown},
		{"notifications.stale_sync_after", c.Notifications.StaleSyncAfter},
	} {
		if !positiveDuration(item.value) {
			return configError(ErrDuration, item.field, nil)
		}
	}
	for _, timeout := range []Duration{
		c.Server.ReadHeaderTimeout, c.Server.ReadTimeout, c.Server.WriteTimeout,
		c.Server.IdleTimeout, c.Server.ShutdownTimeout,
	} {
		if timeout.Duration() > 10*time.Minute {
			return configError(ErrDuration, "server.timeouts", nil)
		}
	}
	if c.Server.ReadinessMaxSyncAge.Duration() > 30*24*time.Hour ||
		c.Server.LAPIUnreachableGrace > c.Server.ReadinessMaxSyncAge {
		return configError(ErrDuration, "server.readiness", nil)
	}
	if c.Schedule.Interval.Duration() > 30*24*time.Hour {
		return configError(ErrDuration, "schedule.interval", nil)
	}
	if c.Database.BusyTimeout.Duration() > time.Minute ||
		c.Database.HistoryRetention.Duration() < time.Hour ||
		c.Database.HistoryRetention.Duration() > 10*365*24*time.Hour {
		return configError(ErrDuration, "database.timeouts", nil)
	}
	if c.CrowdSec.RequestTimeout.Duration() > 2*time.Minute ||
		c.CrowdSec.ConnectTimeout.Duration() > time.Minute {
		return configError(ErrDuration, "crowdsec.timeouts", nil)
	}
	if c.Decisions.Duration.Duration() < time.Minute || c.Decisions.Duration.Duration() > 7*24*time.Hour {
		return configError(ErrDuration, "decisions.duration", nil)
	}
	if c.Notifications.RequestTimeout.Duration() > 2*time.Minute ||
		c.Notifications.StaleSyncAfter.Duration() > 30*24*time.Hour {
		return configError(ErrDuration, "notifications.timeouts", nil)
	}
	if c.Schedule.StartupJitter.Duration() < 0 || c.Schedule.StartupJitter > c.Schedule.Interval {
		return configError(ErrDuration, "schedule.startup_jitter", nil)
	}
	if err := validateRetry("schedule.retry", c.Schedule.Retry); err != nil {
		return err
	}
	if !filepath.IsAbs(c.Database.Path) || c.Database.Path == string(filepath.Separator) {
		return configError(ErrPath, "database.path", nil)
	}
	if c.Database.MaxHistoryEntries < 1 || c.Database.MaxHistoryEntries > 1_000_000 {
		return configError(ErrValidation, "database.max_history_entries", nil)
	}
	if !filepath.IsAbs(c.CrowdSec.CredentialsFile) {
		return configError(ErrPath, "crowdsec.credentials_file", nil)
	}
	allowedHTTPHosts, err := canonicalHTTPHosts(c.CrowdSec.AllowedHTTPHosts)
	if err != nil {
		return err
	}
	c.CrowdSec.AllowedHTTPHosts = allowedHTTPHosts
	if c.CrowdSec.MaxResponseBytes < 1024 || c.CrowdSec.MaxResponseBytes > 64<<20 || c.CrowdSec.BatchSize < 1 || c.CrowdSec.BatchSize > 500 {
		return configError(ErrValidation, "crowdsec.limits", nil)
	}
	if c.CrowdSec.ConnectTimeout > c.CrowdSec.RequestTimeout || c.CrowdSec.AuthRefreshBefore.Duration() >= time.Hour {
		return configError(ErrDuration, "crowdsec.timeouts", nil)
	}
	if c.Decisions.MissingGraceRuns < 1 || c.Decisions.MissingGraceRuns > 100 {
		return configError(ErrValidation, "decisions.missing_grace_runs", nil)
	}
	if c.Decisions.RefreshBefore >= c.Decisions.Duration {
		return configError(ErrDuration, "decisions.refresh_before", nil)
	}
	if c.Validation.MaxRedirects < 0 || c.Validation.MaxRedirects > 10 || c.Validation.MaxFeeds < 1 || c.Validation.MaxFeeds > 256 || c.Validation.MaxFeedNameLength < 1 || c.Validation.MaxFeedNameLength > 128 || c.Validation.MaxLineBytes < 1024 || c.Validation.MaxLineBytes > 1<<20 || c.Validation.MaxMalformedLines < 0 || math.IsNaN(c.Validation.MaxMalformedRatio) || math.IsInf(c.Validation.MaxMalformedRatio, 0) || c.Validation.MaxMalformedRatio < 0 || c.Validation.MaxMalformedRatio > 1 {
		return configError(ErrValidation, "validation", nil)
	}
	if strings.Count(c.Validation.UserAgent, "/") != 1 || len(c.Validation.UserAgent) > 128 || strings.ContainsAny(c.Validation.UserAgent, "\r\n\x00") {
		return configError(ErrValidation, "validation.user_agent", nil)
	}
	if len(c.Feeds) == 0 || len(c.Feeds) > c.Validation.MaxFeeds {
		return configError(ErrValidation, "feeds", nil)
	}
	seenFeeds := make(map[string]struct{}, len(c.Feeds))
	for i := range c.Feeds {
		if c.Feeds[i].MaxMalformedLines == 0 {
			c.Feeds[i].MaxMalformedLines = c.Validation.MaxMalformedLines
		}
		if c.Feeds[i].MaxMalformedRatio == 0 {
			c.Feeds[i].MaxMalformedRatio = c.Validation.MaxMalformedRatio
		}
		name := strings.ToLower(c.Feeds[i].Name)
		if _, exists := seenFeeds[name]; exists {
			return indexedError(ErrFeedName, "feeds", i, nil)
		}
		seenFeeds[name] = struct{}{}
		if err := validateFeed(*c, i, c.Feeds[i]); err != nil {
			return err
		}
	}

	seenCIDRs := make(map[netip.Prefix]struct{}, len(c.Allowlists.CIDRs))
	canonical := make([]CIDR, 0, len(c.Allowlists.CIDRs))
	for i, cidr := range c.Allowlists.CIDRs {
		prefix := cidr.Prefix()
		if !prefix.IsValid() {
			return indexedError(ErrAllowlist, "allowlists.cidrs", i, nil)
		}
		prefix = prefix.Masked()
		if _, exists := seenCIDRs[prefix]; exists {
			continue
		}
		seenCIDRs[prefix] = struct{}{}
		canonical = append(canonical, CIDR{prefix: prefix})
	}
	slices.SortFunc(canonical, func(a, b CIDR) int { return a.Prefix().Compare(b.Prefix()) })
	c.Allowlists.CIDRs = canonical

	if c.Logging.Format != "json" {
		return configError(ErrValidation, "logging.format", nil)
	}
	if c.Logging.Level != "debug" && c.Logging.Level != "info" && c.Logging.Level != "warn" && c.Logging.Level != "error" {
		return configError(ErrValidation, "logging.level", nil)
	}
	if c.Notifications.MinimumSeverity != "info" && c.Notifications.MinimumSeverity != "warning" && c.Notifications.MinimumSeverity != "error" {
		return configError(ErrNotification, "notifications.minimum_severity", nil)
	}
	if c.Notifications.FailureThreshold < 1 || c.Notifications.FailureThreshold > 100 {
		return configError(ErrNotification, "notifications.failure_threshold", nil)
	}
	if c.Notifications.Cooldown.Duration() > 30*24*time.Hour {
		return configError(ErrNotification, "notifications.cooldown", nil)
	}
	if c.Notifications.Enabled {
		if err := validateRemoteURL("notifications.server_url", c.Notifications.ServerURL, c.Notifications.AllowHTTP, c.Validation.AllowHTTP); err != nil {
			return configError(ErrNotification, "notifications.server_url", err)
		}
		if !topicPattern.MatchString(c.Notifications.Topic) {
			return configError(ErrNotification, "notifications.topic", nil)
		}
	}
	return nil
}
