package config

import (
	"strings"
	"testing"
	"time"
)

func TestEnvironmentOverridesUseTypedValidation(t *testing.T) {
	env := []string{
		"CROWDSHIELD_SERVER_LISTEN_ADDRESS=127.0.0.1:19090",
		"CROWDSHIELD_SCHEDULE_INTERVAL=8h",
		"CROWDSHIELD_DATABASE_PATH=/data/development.db",
		"CROWDSHIELD_CROWDSEC_CREDENTIALS_FILE=/run/secrets/development.yaml",
		"CROWDSHIELD_FEED_SPAMHAUS_DROP_IPV6_ENABLED=false",
		"CROWDSHIELD_NOTIFICATIONS_ENABLED=true",
		"CROWDSHIELD_NOTIFICATIONS_SERVER_URL=https://ntfy.example.invalid",
		"CROWDSHIELD_NOTIFICATIONS_TOPIC=crowdshield-dev",
		"CROWDSHIELD_NOTIFICATIONS_COOLDOWN=2h",
		"CROWDSHIELD_NOTIFICATIONS_TOKEN=notification-canary-do-not-emit",
	}
	cfg, err := testLoader(env...).Load(writeConfig(t, "{}\n"))
	if err != nil {
		t.Fatal("supported environment overrides failed")
	}
	if cfg.Server.ListenAddress != "127.0.0.1:19090" || cfg.Schedule.Interval.Duration() != 8*time.Hour {
		t.Fatal("typed scalar override not applied")
	}
	if cfg.Database.Path != "/data/development.db" || cfg.CrowdSec.CredentialsFile != "/run/secrets/development.yaml" {
		t.Fatal("path override not applied")
	}
	if cfg.Feeds[1].Enabled {
		t.Fatal("dynamic feed enable override not applied")
	}
	if !cfg.Notifications.Enabled || cfg.Notifications.Token.Reveal() != "notification-canary-do-not-emit" || cfg.Notifications.Cooldown.Duration() != 2*time.Hour {
		t.Fatal("notification environment override not applied")
	}
}

func TestEnvironmentRejectsUnusedCrowdSecRetryOverride(t *testing.T) {
	_, err := testLoader("CROWDSHIELD_CROWDSEC_RETRY_MAX_ATTEMPTS=9").Load(writeConfig(t, "{}\n"))
	if err == nil || !IsCategory(err, ErrEnvironment) {
		t.Fatal("unused CrowdSec retry override was accepted")
	}
}

func TestEnvironmentRejectsUnknownCrowdshieldVariable(t *testing.T) {
	const canary = "value-canary-do-not-emit"
	_, err := testLoader("CROWDSHIELD_UNKNOWN_SETTING=" + canary).Load(writeConfig(t, "{}\n"))
	if err == nil || !IsCategory(err, ErrEnvironment) {
		t.Fatal("unknown environment override accepted")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("environment error disclosed value")
	}
}

func TestEnvironmentRejectsInvalidBooleanWithoutValueLeak(t *testing.T) {
	const canary = "not-a-boolean-canary"
	_, err := testLoader("CROWDSHIELD_NOTIFICATIONS_ENABLED=" + canary).Load(writeConfig(t, "{}\n"))
	if err == nil || !IsCategory(err, ErrEnvironment) {
		t.Fatal("invalid boolean override accepted")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("environment parse error disclosed value")
	}
}

func TestConfigPathVariableIsReservedForCLI(t *testing.T) {
	cfg, err := testLoader("CROWDSHIELD_CONFIG=/config/alternate.yaml").Load(writeConfig(t, "{}\n"))
	if err != nil {
		t.Fatal("reserved config path variable was rejected")
	}
	if cfg.Server.ListenAddress != ":9090" {
		t.Fatal("reserved variable unexpectedly changed configuration")
	}
}
