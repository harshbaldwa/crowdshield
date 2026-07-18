package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLoader(env ...string) Loader {
	return Loader{
		Version:  "test",
		MaxBytes: DefaultMaxConfigBytes,
		Environ: func() []string {
			return append([]string(nil), env...)
		},
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crowdshield.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal("unable to create configuration fixture")
	}
	return path
}

func TestLoadDefaultsAreConservativeAndComplete(t *testing.T) {
	cfg, err := testLoader().Load(writeConfig(t, "{}\n"))
	if err != nil {
		t.Fatal("default configuration did not validate")
	}
	if cfg.Server.ListenAddress != ":9090" {
		t.Fatal("unexpected metrics listener default")
	}
	if cfg.Schedule.Interval.Duration() != 6*time.Hour || cfg.Schedule.StartupJitter.Duration() != 10*time.Minute || !cfg.Schedule.RunImmediately {
		t.Fatal("unexpected scheduling defaults")
	}
	if cfg.Decisions.Duration.Duration() != 25*time.Hour || cfg.Decisions.MissingGraceRuns != 2 || cfg.Decisions.RefreshBefore.Duration() >= cfg.Decisions.Duration.Duration() {
		t.Fatal("unexpected decision defaults")
	}
	if len(cfg.Feeds) != 3 {
		t.Fatal("default feed count changed")
	}
	for i := range cfg.Feeds {
		if !cfg.Feeds[i].Enabled {
			t.Fatal("requested default feed is not enabled")
		}
		if cfg.Feeds[i].Attribution == "" || cfg.Feeds[i].URL == "" {
			t.Fatal("default feed lacks reviewed identity")
		}
	}
	if cfg.Feeds[0].Name != "spamhaus-drop-ipv4" || cfg.Feeds[1].Name != "spamhaus-drop-ipv6" || cfg.Feeds[2].Name != "firehol-level1" {
		t.Fatal("unexpected default feed set or order")
	}
	if cfg.Notifications.Enabled || cfg.Notifications.SuccessNotification || cfg.Notifications.Cooldown.Duration() != time.Hour {
		t.Fatal("notifications are not conservative by default")
	}
}

func TestExampleConfigurationLoads(t *testing.T) {
	path := filepath.Join("..", "..", "config", "crowdshield.example.yaml")
	cfg, err := testLoader().Load(path)
	if err != nil {
		t.Fatal("checked-in example configuration is invalid")
	}
	if len(cfg.Feeds) != 3 || cfg.Logging.Format != "json" {
		t.Fatal("checked-in example lost required sections")
	}
}

func TestLoadRejectsUnknownFieldWithoutEchoingValue(t *testing.T) {
	const canary = "credential-canary-do-not-emit"
	_, err := testLoader().Load(writeConfig(t, "logging:\n  level: info\n  password: "+canary+"\n"))
	if err == nil {
		t.Fatal("unknown field accepted")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("configuration error disclosed a value")
	}
}

func TestLoadRejectsSecondYAMLDocument(t *testing.T) {
	_, err := testLoader().Load(writeConfig(t, "{}\n---\n{}\n"))
	if err == nil || !IsCategory(err, ErrYAMLDocument) {
		t.Fatal("second YAML document was not rejected")
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	loader := testLoader()
	loader.MaxBytes = 32
	_, err := loader.Load(writeConfig(t, "# "+strings.Repeat("x", 64)+"\n"))
	if err == nil || !IsCategory(err, ErrConfigSize) {
		t.Fatal("oversized configuration was not rejected")
	}
}

func TestConfigRejectsDuplicateFeedNames(t *testing.T) {
	cfg := Defaults("test")
	cfg.Feeds = append(cfg.Feeds, cfg.Feeds[0])
	if err := cfg.Validate(); err == nil || !IsCategory(err, ErrFeedName) {
		t.Fatal("duplicate feed name accepted")
	}
}

func TestConfigRejectsUnsafeOrMalformedFeedURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "plain HTTP", url: "http://feed.example.invalid/list"},
		{name: "userinfo", url: "https://user@example.invalid/list"},
		{name: "fragment", url: "https://feed.example.invalid/list#fragment"},
		{name: "relative", url: "/list"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults("test")
			cfg.Feeds[0].URL = tc.url
			if err := cfg.Validate(); err == nil || !IsCategory(err, ErrFeedURL) {
				t.Fatal("unsafe feed URL accepted")
			}
		})
	}
}

func TestHTTPRequiresGlobalAndPerFeedOptIn(t *testing.T) {
	cfg := Defaults("test")
	cfg.Feeds[0].URL = "http://feed.example.invalid/list"
	cfg.Validation.AllowHTTP = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("global HTTP opt-in alone was sufficient")
	}
	cfg.Feeds[0].AllowHTTP = true
	if err := cfg.Validate(); err != nil {
		t.Fatal("explicit two-level HTTP opt-in was rejected")
	}
}

func TestCrowdSecHTTPHostsAreExactBoundedAndCanonical(t *testing.T) {
	cfg := Defaults("test")
	cfg.CrowdSec.AllowedHTTPHosts = []string{"LAPI.Internal.", "crowdsec"}
	if err := cfg.Validate(); err != nil {
		t.Fatal("valid exact CrowdSec HTTP hosts were rejected")
	}
	if len(cfg.CrowdSec.AllowedHTTPHosts) != 2 || cfg.CrowdSec.AllowedHTTPHosts[0] != "crowdsec" || cfg.CrowdSec.AllowedHTTPHosts[1] != "lapi.internal" {
		t.Fatal("CrowdSec HTTP hosts were not canonicalized deterministically")
	}

	invalid := []string{"", "http://crowdsec", "crowdsec:8080", "crowdsec/path", "-crowdsec", "crowdsec-"}
	for _, host := range invalid {
		cfg := Defaults("test")
		cfg.CrowdSec.AllowedHTTPHosts = []string{host}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe CrowdSec HTTP host accepted: %q", host)
		}
	}
	cfg = Defaults("test")
	cfg.CrowdSec.AllowedHTTPHosts = make([]string, 17)
	for index := range cfg.CrowdSec.AllowedHTTPHosts {
		cfg.CrowdSec.AllowedHTTPHosts[index] = fmt.Sprintf("lapi-%d.internal", index)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unbounded CrowdSec HTTP host list accepted")
	}
}

func TestConfigThresholdValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "zero interval", mutate: func(c *Config) { c.Schedule.Interval = 0 }},
		{name: "jitter exceeds interval", mutate: func(c *Config) { c.Schedule.StartupJitter = Duration(7 * time.Hour) }},
		{name: "refresh exceeds TTL", mutate: func(c *Config) { c.Decisions.RefreshBefore = c.Decisions.Duration }},
		{name: "missing grace zero", mutate: func(c *Config) { c.Decisions.MissingGraceRuns = 0 }},
		{name: "entry bounds reversed", mutate: func(c *Config) { c.Feeds[0].ExpectedMinEntries = c.Feeds[0].ExpectedMaxEntries + 1 }},
		{name: "growth below one", mutate: func(c *Config) { c.Feeds[0].MaxGrowthRatio = 0.9 }},
		{name: "shrink above one", mutate: func(c *Config) { c.Feeds[0].MaxShrinkRatio = 1.1 }},
		{name: "body size zero", mutate: func(c *Config) { c.Feeds[0].MaxDownloadBytes = 0 }},
		{name: "batch zero", mutate: func(c *Config) { c.CrowdSec.BatchSize = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults("test")
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid threshold accepted")
			}
		})
	}
}

func TestCIDRAllowlistsOnlyAndCanonicalization(t *testing.T) {
	path := writeConfig(t, "allowlists:\n  cidrs:\n    - 198.51.100.99/24\n")
	cfg, err := testLoader().Load(path)
	if err != nil {
		t.Fatal("valid CIDR allowlist rejected")
	}
	if len(cfg.Allowlists.CIDRs) != 1 || cfg.Allowlists.CIDRs[0].String() != "198.51.100.0/24" {
		t.Fatal("allowlist CIDR was not canonicalized")
	}

	_, err = testLoader().Load(writeConfig(t, "allowlists:\n  cidrs:\n    - 198.51.100.9\n"))
	if err == nil || !IsCategory(err, ErrAllowlist) {
		t.Fatal("bare-address allowlist accepted")
	}
}

func TestSecretCannotBeFormatted(t *testing.T) {
	secret := NewSecret("credential-canary-do-not-emit")
	for _, rendered := range []string{
		fmt.Sprint(secret),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret),
		fmt.Sprintf("%#v", secret),
	} {
		if strings.Contains(rendered, "credential-canary") {
			t.Fatal("secret formatting disclosed value")
		}
	}
	if secret.Reveal() != "credential-canary-do-not-emit" {
		t.Fatal("secret accessor lost value")
	}
}
