package config

import (
	"strconv"
	"strings"
	"time"
)

type envSetter func(*Config, string) error

func envFailure(key string, cause error) error {
	return configError(ErrEnvironment, key, cause)
}

func parseBoolEnv(key, value string) (bool, error) {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, envFailure(key, err)
	}
	return parsed, nil
}

func parseIntEnv(key, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, envFailure(key, err)
	}
	return parsed, nil
}

func parseInt64Env(key, value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, envFailure(key, err)
	}
	return parsed, nil
}

func parseFloatEnv(key, value string) (float64, error) {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, envFailure(key, err)
	}
	return parsed, nil
}

func parseDurationEnv(key, value string) (Duration, error) {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, envFailure(key, err)
	}
	return Duration(parsed), nil
}

func durationSetter(key string, target func(*Config) *Duration) envSetter {
	return func(c *Config, value string) error {
		parsed, err := parseDurationEnv(key, value)
		if err != nil {
			return err
		}
		*target(c) = parsed
		return nil
	}
}

func boolSetter(key string, target func(*Config) *bool) envSetter {
	return func(c *Config, value string) error {
		parsed, err := parseBoolEnv(key, value)
		if err != nil {
			return err
		}
		*target(c) = parsed
		return nil
	}
}

func intSetter(key string, target func(*Config) *int) envSetter {
	return func(c *Config, value string) error {
		parsed, err := parseIntEnv(key, value)
		if err != nil {
			return err
		}
		*target(c) = parsed
		return nil
	}
}

func int64Setter(key string, target func(*Config) *int64) envSetter {
	return func(c *Config, value string) error {
		parsed, err := parseInt64Env(key, value)
		if err != nil {
			return err
		}
		*target(c) = parsed
		return nil
	}
}

func floatSetter(key string, target func(*Config) *float64) envSetter {
	return func(c *Config, value string) error {
		parsed, err := parseFloatEnv(key, value)
		if err != nil {
			return err
		}
		*target(c) = parsed
		return nil
	}
}

func stringSetter(target func(*Config) *string) envSetter {
	return func(c *Config, value string) error {
		*target(c) = value
		return nil
	}
}

func supportedEnvironment() map[string]envSetter {
	setters := map[string]envSetter{}
	setters["CROWDSHIELD_SERVER_LISTEN_ADDRESS"] = stringSetter(func(c *Config) *string { return &c.Server.ListenAddress })
	setters["CROWDSHIELD_SERVER_READ_HEADER_TIMEOUT"] = durationSetter("CROWDSHIELD_SERVER_READ_HEADER_TIMEOUT", func(c *Config) *Duration { return &c.Server.ReadHeaderTimeout })
	setters["CROWDSHIELD_SERVER_READ_TIMEOUT"] = durationSetter("CROWDSHIELD_SERVER_READ_TIMEOUT", func(c *Config) *Duration { return &c.Server.ReadTimeout })
	setters["CROWDSHIELD_SERVER_WRITE_TIMEOUT"] = durationSetter("CROWDSHIELD_SERVER_WRITE_TIMEOUT", func(c *Config) *Duration { return &c.Server.WriteTimeout })
	setters["CROWDSHIELD_SERVER_IDLE_TIMEOUT"] = durationSetter("CROWDSHIELD_SERVER_IDLE_TIMEOUT", func(c *Config) *Duration { return &c.Server.IdleTimeout })
	setters["CROWDSHIELD_SERVER_SHUTDOWN_TIMEOUT"] = durationSetter("CROWDSHIELD_SERVER_SHUTDOWN_TIMEOUT", func(c *Config) *Duration { return &c.Server.ShutdownTimeout })
	setters["CROWDSHIELD_SERVER_LAPI_UNREACHABLE_GRACE"] = durationSetter("CROWDSHIELD_SERVER_LAPI_UNREACHABLE_GRACE", func(c *Config) *Duration { return &c.Server.LAPIUnreachableGrace })
	setters["CROWDSHIELD_SERVER_READINESS_MAX_SYNC_AGE"] = durationSetter("CROWDSHIELD_SERVER_READINESS_MAX_SYNC_AGE", func(c *Config) *Duration { return &c.Server.ReadinessMaxSyncAge })

	setters["CROWDSHIELD_SCHEDULE_INTERVAL"] = durationSetter("CROWDSHIELD_SCHEDULE_INTERVAL", func(c *Config) *Duration { return &c.Schedule.Interval })
	setters["CROWDSHIELD_SCHEDULE_STARTUP_JITTER"] = durationSetter("CROWDSHIELD_SCHEDULE_STARTUP_JITTER", func(c *Config) *Duration { return &c.Schedule.StartupJitter })
	setters["CROWDSHIELD_SCHEDULE_RUN_IMMEDIATELY"] = boolSetter("CROWDSHIELD_SCHEDULE_RUN_IMMEDIATELY", func(c *Config) *bool { return &c.Schedule.RunImmediately })
	setters["CROWDSHIELD_SCHEDULE_RETRY_MAX_ATTEMPTS"] = intSetter("CROWDSHIELD_SCHEDULE_RETRY_MAX_ATTEMPTS", func(c *Config) *int { return &c.Schedule.Retry.MaxAttempts })
	setters["CROWDSHIELD_SCHEDULE_RETRY_INITIAL_BACKOFF"] = durationSetter("CROWDSHIELD_SCHEDULE_RETRY_INITIAL_BACKOFF", func(c *Config) *Duration { return &c.Schedule.Retry.InitialBackoff })
	setters["CROWDSHIELD_SCHEDULE_RETRY_MAX_BACKOFF"] = durationSetter("CROWDSHIELD_SCHEDULE_RETRY_MAX_BACKOFF", func(c *Config) *Duration { return &c.Schedule.Retry.MaxBackoff })

	setters["CROWDSHIELD_DATABASE_PATH"] = stringSetter(func(c *Config) *string { return &c.Database.Path })
	setters["CROWDSHIELD_DATABASE_BUSY_TIMEOUT"] = durationSetter("CROWDSHIELD_DATABASE_BUSY_TIMEOUT", func(c *Config) *Duration { return &c.Database.BusyTimeout })
	setters["CROWDSHIELD_DATABASE_INTEGRITY_CHECK_ON_STARTUP"] = boolSetter("CROWDSHIELD_DATABASE_INTEGRITY_CHECK_ON_STARTUP", func(c *Config) *bool { return &c.Database.IntegrityCheckOnStart })
	setters["CROWDSHIELD_DATABASE_HISTORY_RETENTION"] = durationSetter("CROWDSHIELD_DATABASE_HISTORY_RETENTION", func(c *Config) *Duration { return &c.Database.HistoryRetention })
	setters["CROWDSHIELD_DATABASE_MAX_HISTORY_ENTRIES"] = intSetter("CROWDSHIELD_DATABASE_MAX_HISTORY_ENTRIES", func(c *Config) *int { return &c.Database.MaxHistoryEntries })

	setters["CROWDSHIELD_CROWDSEC_CREDENTIALS_FILE"] = stringSetter(func(c *Config) *string { return &c.CrowdSec.CredentialsFile })
	setters["CROWDSHIELD_CROWDSEC_REQUEST_TIMEOUT"] = durationSetter("CROWDSHIELD_CROWDSEC_REQUEST_TIMEOUT", func(c *Config) *Duration { return &c.CrowdSec.RequestTimeout })
	setters["CROWDSHIELD_CROWDSEC_CONNECT_TIMEOUT"] = durationSetter("CROWDSHIELD_CROWDSEC_CONNECT_TIMEOUT", func(c *Config) *Duration { return &c.CrowdSec.ConnectTimeout })
	setters["CROWDSHIELD_CROWDSEC_MAX_RESPONSE_BYTES"] = int64Setter("CROWDSHIELD_CROWDSEC_MAX_RESPONSE_BYTES", func(c *Config) *int64 { return &c.CrowdSec.MaxResponseBytes })
	setters["CROWDSHIELD_CROWDSEC_BATCH_SIZE"] = intSetter("CROWDSHIELD_CROWDSEC_BATCH_SIZE", func(c *Config) *int { return &c.CrowdSec.BatchSize })
	setters["CROWDSHIELD_CROWDSEC_AUTH_REFRESH_BEFORE"] = durationSetter("CROWDSHIELD_CROWDSEC_AUTH_REFRESH_BEFORE", func(c *Config) *Duration { return &c.CrowdSec.AuthRefreshBefore })

	setters["CROWDSHIELD_DECISIONS_DURATION"] = durationSetter("CROWDSHIELD_DECISIONS_DURATION", func(c *Config) *Duration { return &c.Decisions.Duration })
	setters["CROWDSHIELD_DECISIONS_MISSING_GRACE_RUNS"] = intSetter("CROWDSHIELD_DECISIONS_MISSING_GRACE_RUNS", func(c *Config) *int { return &c.Decisions.MissingGraceRuns })
	setters["CROWDSHIELD_DECISIONS_REFRESH_BEFORE"] = durationSetter("CROWDSHIELD_DECISIONS_REFRESH_BEFORE", func(c *Config) *Duration { return &c.Decisions.RefreshBefore })

	setters["CROWDSHIELD_VALIDATION_ALLOW_HTTP"] = boolSetter("CROWDSHIELD_VALIDATION_ALLOW_HTTP", func(c *Config) *bool { return &c.Validation.AllowHTTP })
	setters["CROWDSHIELD_VALIDATION_MAX_REDIRECTS"] = intSetter("CROWDSHIELD_VALIDATION_MAX_REDIRECTS", func(c *Config) *int { return &c.Validation.MaxRedirects })
	setters["CROWDSHIELD_VALIDATION_MAX_FEEDS"] = intSetter("CROWDSHIELD_VALIDATION_MAX_FEEDS", func(c *Config) *int { return &c.Validation.MaxFeeds })
	setters["CROWDSHIELD_VALIDATION_MAX_FEED_NAME_LENGTH"] = intSetter("CROWDSHIELD_VALIDATION_MAX_FEED_NAME_LENGTH", func(c *Config) *int { return &c.Validation.MaxFeedNameLength })
	setters["CROWDSHIELD_VALIDATION_MAX_MALFORMED_LINES"] = intSetter("CROWDSHIELD_VALIDATION_MAX_MALFORMED_LINES", func(c *Config) *int { return &c.Validation.MaxMalformedLines })
	setters["CROWDSHIELD_VALIDATION_MAX_MALFORMED_RATIO"] = floatSetter("CROWDSHIELD_VALIDATION_MAX_MALFORMED_RATIO", func(c *Config) *float64 { return &c.Validation.MaxMalformedRatio })
	setters["CROWDSHIELD_VALIDATION_MAX_LINE_BYTES"] = intSetter("CROWDSHIELD_VALIDATION_MAX_LINE_BYTES", func(c *Config) *int { return &c.Validation.MaxLineBytes })
	setters["CROWDSHIELD_VALIDATION_USER_AGENT"] = stringSetter(func(c *Config) *string { return &c.Validation.UserAgent })
	setters["CROWDSHIELD_VALIDATION_DNS_LOOKUP_TIMEOUT"] = durationSetter("CROWDSHIELD_VALIDATION_DNS_LOOKUP_TIMEOUT", func(c *Config) *Duration { return &c.Validation.DNSLookupTimeout })

	setters["CROWDSHIELD_LOGGING_LEVEL"] = stringSetter(func(c *Config) *string { return &c.Logging.Level })

	setters["CROWDSHIELD_NOTIFICATIONS_ENABLED"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_ENABLED", func(c *Config) *bool { return &c.Notifications.Enabled })
	setters["CROWDSHIELD_NOTIFICATIONS_SERVER_URL"] = stringSetter(func(c *Config) *string { return &c.Notifications.ServerURL })
	setters["CROWDSHIELD_NOTIFICATIONS_TOPIC"] = stringSetter(func(c *Config) *string { return &c.Notifications.Topic })
	setters["CROWDSHIELD_NOTIFICATIONS_ALLOW_HTTP"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_ALLOW_HTTP", func(c *Config) *bool { return &c.Notifications.AllowHTTP })
	setters["CROWDSHIELD_NOTIFICATIONS_REQUEST_TIMEOUT"] = durationSetter("CROWDSHIELD_NOTIFICATIONS_REQUEST_TIMEOUT", func(c *Config) *Duration { return &c.Notifications.RequestTimeout })
	setters["CROWDSHIELD_NOTIFICATIONS_COOLDOWN"] = durationSetter("CROWDSHIELD_NOTIFICATIONS_COOLDOWN", func(c *Config) *Duration { return &c.Notifications.Cooldown })
	setters["CROWDSHIELD_NOTIFICATIONS_MINIMUM_SEVERITY"] = stringSetter(func(c *Config) *string { return &c.Notifications.MinimumSeverity })
	setters["CROWDSHIELD_NOTIFICATIONS_FAILURE_THRESHOLD"] = intSetter("CROWDSHIELD_NOTIFICATIONS_FAILURE_THRESHOLD", func(c *Config) *int { return &c.Notifications.FailureThreshold })
	setters["CROWDSHIELD_NOTIFICATIONS_RECOVERY_NOTIFICATIONS"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_RECOVERY_NOTIFICATIONS", func(c *Config) *bool { return &c.Notifications.RecoveryNotifications })
	setters["CROWDSHIELD_NOTIFICATIONS_SUSPICIOUS_CHANGE_NOTIFICATIONS"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_SUSPICIOUS_CHANGE_NOTIFICATIONS", func(c *Config) *bool { return &c.Notifications.SuspiciousChangeNotifications })
	setters["CROWDSHIELD_NOTIFICATIONS_STALE_SYNC_NOTIFICATIONS"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_STALE_SYNC_NOTIFICATIONS", func(c *Config) *bool { return &c.Notifications.StaleSyncNotifications })
	setters["CROWDSHIELD_NOTIFICATIONS_STALE_SYNC_AFTER"] = durationSetter("CROWDSHIELD_NOTIFICATIONS_STALE_SYNC_AFTER", func(c *Config) *Duration { return &c.Notifications.StaleSyncAfter })
	setters["CROWDSHIELD_NOTIFICATIONS_STARTUP_NOTIFICATION"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_STARTUP_NOTIFICATION", func(c *Config) *bool { return &c.Notifications.StartupNotification })
	setters["CROWDSHIELD_NOTIFICATIONS_SUCCESS_NOTIFICATION"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_SUCCESS_NOTIFICATION", func(c *Config) *bool { return &c.Notifications.SuccessNotification })
	setters["CROWDSHIELD_NOTIFICATIONS_FIRST_SUCCESS_NOTIFICATION"] = boolSetter("CROWDSHIELD_NOTIFICATIONS_FIRST_SUCCESS_NOTIFICATION", func(c *Config) *bool { return &c.Notifications.FirstSuccessNotification })
	setters["CROWDSHIELD_NOTIFICATIONS_TOKEN"] = func(c *Config, value string) error {
		c.Notifications.Token = NewSecret(value)
		return nil
	}
	return setters
}

func applyFeedEnvironment(c *Config, key, value string) (bool, error) {
	const prefix = "CROWDSHIELD_FEED_"
	const suffix = "_ENABLED"
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return false, nil
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
	for i := range c.Feeds {
		name := strings.ToUpper(strings.ReplaceAll(c.Feeds[i].Name, "-", "_"))
		if encoded != name {
			continue
		}
		parsed, err := parseBoolEnv(key, value)
		if err != nil {
			return true, err
		}
		c.Feeds[i].Enabled = parsed
		return true, nil
	}
	return true, envFailure(key, nil)
}

func applyEnvironment(c *Config, entries []string) error {
	setters := supportedEnvironment()
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "CROWDSHIELD_") {
			continue
		}
		if !ok {
			return envFailure(key, nil)
		}
		if key == "CROWDSHIELD_CONFIG" {
			continue
		}
		if setter, exists := setters[key]; exists {
			if err := setter(c, value); err != nil {
				return err
			}
			continue
		}
		handled, err := applyFeedEnvironment(c, key, value)
		if err != nil {
			return err
		}
		if handled {
			continue
		}
		return envFailure(key, nil)
	}
	return nil
}
