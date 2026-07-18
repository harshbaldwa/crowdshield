package config

import (
	"regexp"
	"strings"
	"time"
)

const (
	DefaultPath           = "/config/crowdshield.yaml"
	DefaultMaxConfigBytes = int64(1 << 20)
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Schedule      ScheduleConfig      `yaml:"schedule"`
	Database      DatabaseConfig      `yaml:"database"`
	CrowdSec      CrowdSecConfig      `yaml:"crowdsec"`
	Decisions     DecisionsConfig     `yaml:"decisions"`
	Feeds         []FeedConfig        `yaml:"feeds"`
	Allowlists    AllowlistsConfig    `yaml:"allowlists"`
	Validation    ValidationConfig    `yaml:"validation"`
	Logging       LoggingConfig       `yaml:"logging"`
	Notifications NotificationsConfig `yaml:"notifications"`
}

type ServerConfig struct {
	ListenAddress        string   `yaml:"listen_address"`
	ReadHeaderTimeout    Duration `yaml:"read_header_timeout"`
	ReadTimeout          Duration `yaml:"read_timeout"`
	WriteTimeout         Duration `yaml:"write_timeout"`
	IdleTimeout          Duration `yaml:"idle_timeout"`
	ShutdownTimeout      Duration `yaml:"shutdown_timeout"`
	LAPIUnreachableGrace Duration `yaml:"lapi_unreachable_grace"`
	ReadinessMaxSyncAge  Duration `yaml:"readiness_max_sync_age"`
}

type RetryConfig struct {
	MaxAttempts    int      `yaml:"max_attempts"`
	InitialBackoff Duration `yaml:"initial_backoff"`
	MaxBackoff     Duration `yaml:"max_backoff"`
}

type ScheduleConfig struct {
	Interval       Duration    `yaml:"interval"`
	StartupJitter  Duration    `yaml:"startup_jitter"`
	RunImmediately bool        `yaml:"run_immediately"`
	Retry          RetryConfig `yaml:"retry"`
}

type DatabaseConfig struct {
	Path                  string   `yaml:"path"`
	BusyTimeout           Duration `yaml:"busy_timeout"`
	IntegrityCheckOnStart bool     `yaml:"integrity_check_on_startup"`
	HistoryRetention      Duration `yaml:"history_retention"`
	MaxHistoryEntries     int      `yaml:"max_history_entries"`
}

type CrowdSecConfig struct {
	CredentialsFile   string      `yaml:"credentials_file"`
	AllowedHTTPHosts  []string    `yaml:"allowed_http_hosts"`
	RequestTimeout    Duration    `yaml:"request_timeout"`
	ConnectTimeout    Duration    `yaml:"connect_timeout"`
	MaxResponseBytes  int64       `yaml:"max_response_bytes"`
	BatchSize         int         `yaml:"batch_size"`
	AuthRefreshBefore Duration    `yaml:"auth_refresh_before"`
	Retry             RetryConfig `yaml:"retry"`
}

type DecisionsConfig struct {
	Duration         Duration `yaml:"duration"`
	MissingGraceRuns int      `yaml:"missing_grace_runs"`
	RefreshBefore    Duration `yaml:"refresh_before"`
}

type FeedConfig struct {
	Name                string   `yaml:"name"`
	Enabled             bool     `yaml:"enabled"`
	URL                 string   `yaml:"url"`
	Format              string   `yaml:"format"`
	Family              string   `yaml:"family"`
	Timeout             Duration `yaml:"timeout"`
	MaxDownloadBytes    int64    `yaml:"max_download_bytes"`
	ExpectedMinEntries  int      `yaml:"expected_min_entries"`
	ExpectedMaxEntries  int      `yaml:"expected_max_entries"`
	MaxGrowthRatio      float64  `yaml:"max_growth_ratio"`
	MaxShrinkRatio      float64  `yaml:"max_shrink_ratio"`
	Attribution         string   `yaml:"attribution"`
	MinUpdateInterval   Duration `yaml:"min_update_interval"`
	AllowHTTP           bool     `yaml:"allow_http"`
	ContentTypes        []string `yaml:"content_types"`
	RequireFinalNewline bool     `yaml:"require_final_newline"`
	MaxMalformedLines   int      `yaml:"max_malformed_lines"`
	MaxMalformedRatio   float64  `yaml:"max_malformed_ratio"`
}

type AllowlistsConfig struct {
	CIDRs []CIDR `yaml:"cidrs"`
}

type ValidationConfig struct {
	AllowHTTP         bool     `yaml:"allow_http"`
	MaxRedirects      int      `yaml:"max_redirects"`
	MaxFeeds          int      `yaml:"max_feeds"`
	MaxFeedNameLength int      `yaml:"max_feed_name_length"`
	MaxMalformedLines int      `yaml:"max_malformed_lines"`
	MaxMalformedRatio float64  `yaml:"max_malformed_ratio"`
	MaxLineBytes      int      `yaml:"max_line_bytes"`
	UserAgent         string   `yaml:"user_agent"`
	DNSLookupTimeout  Duration `yaml:"dns_lookup_timeout"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type NotificationsConfig struct {
	Enabled                       bool     `yaml:"enabled"`
	ServerURL                     string   `yaml:"server_url"`
	Topic                         string   `yaml:"topic"`
	AllowHTTP                     bool     `yaml:"allow_http"`
	RequestTimeout                Duration `yaml:"request_timeout"`
	Cooldown                      Duration `yaml:"cooldown"`
	MinimumSeverity               string   `yaml:"minimum_severity"`
	FailureThreshold              int      `yaml:"failure_threshold"`
	RecoveryNotifications         bool     `yaml:"recovery_notifications"`
	SuspiciousChangeNotifications bool     `yaml:"suspicious_change_notifications"`
	StaleSyncNotifications        bool     `yaml:"stale_sync_notifications"`
	StaleSyncAfter                Duration `yaml:"stale_sync_after"`
	StartupNotification           bool     `yaml:"startup_notification"`
	SuccessNotification           bool     `yaml:"success_notification"`
	FirstSuccessNotification      bool     `yaml:"first_success_notification"`
	Token                         Secret   `yaml:"-"`
}

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

func userAgent(version string) string {
	version = strings.TrimSpace(version)
	if !safeVersion.MatchString(version) {
		version = "dev"
	}
	return "crowdshield/" + version
}

// Defaults returns a complete conservative configuration.
func Defaults(version string) Config {
	return Config{
		Server: ServerConfig{
			ListenAddress:        ":9090",
			ReadHeaderTimeout:    Duration(5 * time.Second),
			ReadTimeout:          Duration(10 * time.Second),
			WriteTimeout:         Duration(30 * time.Second),
			IdleTimeout:          Duration(60 * time.Second),
			ShutdownTimeout:      Duration(10 * time.Second),
			LAPIUnreachableGrace: Duration(15 * time.Minute),
			ReadinessMaxSyncAge:  Duration(12 * time.Hour),
		},
		Schedule: ScheduleConfig{
			Interval:       Duration(6 * time.Hour),
			StartupJitter:  Duration(10 * time.Minute),
			RunImmediately: true,
			Retry: RetryConfig{
				MaxAttempts:    3,
				InitialBackoff: Duration(30 * time.Second),
				MaxBackoff:     Duration(5 * time.Minute),
			},
		},
		Database: DatabaseConfig{
			Path:                  "/data/crowdshield.db",
			BusyTimeout:           Duration(5 * time.Second),
			IntegrityCheckOnStart: true,
			HistoryRetention:      Duration(30 * 24 * time.Hour),
			MaxHistoryEntries:     1000,
		},
		CrowdSec: CrowdSecConfig{
			CredentialsFile:   "/run/secrets/crowdshield-lapi-credentials.yaml",
			RequestTimeout:    Duration(15 * time.Second),
			ConnectTimeout:    Duration(5 * time.Second),
			MaxResponseBytes:  8 << 20,
			BatchSize:         250,
			AuthRefreshBefore: Duration(5 * time.Minute),
			Retry: RetryConfig{
				MaxAttempts:    3,
				InitialBackoff: Duration(time.Second),
				MaxBackoff:     Duration(30 * time.Second),
			},
		},
		Decisions: DecisionsConfig{
			Duration:         Duration(25 * time.Hour),
			MissingGraceRuns: 2,
			RefreshBefore:    Duration(12 * time.Hour),
		},
		Feeds: []FeedConfig{
			{
				Name:                "spamhaus-drop-ipv4",
				Enabled:             true,
				URL:                 "https://www.spamhaus.org/drop/drop_v4.json",
				Format:              "spamhaus-drop-jsonl",
				Family:              "ipv4",
				Timeout:             Duration(30 * time.Second),
				MaxDownloadBytes:    2 << 20,
				ExpectedMinEntries:  500,
				ExpectedMaxEntries:  5000,
				MaxGrowthRatio:      1.5,
				MaxShrinkRatio:      0.5,
				Attribution:         "The Spamhaus Project DROP; https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
				MinUpdateInterval:   Duration(24 * time.Hour),
				ContentTypes:        []string{"text/json", "application/json", "application/x-ndjson"},
				RequireFinalNewline: true,
			},
			{
				Name:                "spamhaus-drop-ipv6",
				Enabled:             true,
				URL:                 "https://www.spamhaus.org/drop/drop_v6.json",
				Format:              "spamhaus-drop-jsonl",
				Family:              "ipv6",
				Timeout:             Duration(30 * time.Second),
				MaxDownloadBytes:    1 << 20,
				ExpectedMinEntries:  20,
				ExpectedMaxEntries:  1000,
				MaxGrowthRatio:      1.5,
				MaxShrinkRatio:      0.5,
				Attribution:         "The Spamhaus Project DROP; https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
				MinUpdateInterval:   Duration(24 * time.Hour),
				ContentTypes:        []string{"text/json", "application/json", "application/x-ndjson"},
				RequireFinalNewline: true,
			},
			{
				Name:                "firehol-level1",
				Enabled:             true,
				URL:                 "https://iplists.firehol.org/files/firehol_level1.netset",
				Format:              "firehol-netset",
				Family:              "ipv4",
				Timeout:             Duration(30 * time.Second),
				MaxDownloadBytes:    5 << 20,
				ExpectedMinEntries:  1000,
				ExpectedMaxEntries:  20000,
				MaxGrowthRatio:      1.5,
				MaxShrinkRatio:      0.5,
				Attribution:         "FireHOL Level 1 (DShield, Feodo Tracker, Team Cymru FullBogons, Spamhaus DROP); https://iplists.firehol.org/?ipset=firehol_level1",
				MinUpdateInterval:   Duration(6 * time.Hour),
				ContentTypes:        []string{"application/octet-stream", "text/plain"},
				RequireFinalNewline: true,
			},
		},
		Allowlists: AllowlistsConfig{CIDRs: []CIDR{}},
		Validation: ValidationConfig{
			AllowHTTP:         false,
			MaxRedirects:      3,
			MaxFeeds:          32,
			MaxFeedNameLength: 64,
			MaxMalformedLines: 10,
			MaxMalformedRatio: 0.01,
			MaxLineBytes:      64 << 10,
			UserAgent:         userAgent(version),
			DNSLookupTimeout:  Duration(5 * time.Second),
		},
		Logging: LoggingConfig{Level: "info", Format: "json"},
		Notifications: NotificationsConfig{
			Enabled:                       false,
			RequestTimeout:                Duration(10 * time.Second),
			Cooldown:                      Duration(time.Hour),
			MinimumSeverity:               "warning",
			FailureThreshold:              3,
			RecoveryNotifications:         true,
			SuspiciousChangeNotifications: true,
			StaleSyncNotifications:        true,
			StaleSyncAfter:                Duration(12 * time.Hour),
			StartupNotification:           false,
			SuccessNotification:           false,
			FirstSuccessNotification:      false,
		},
	}
}
