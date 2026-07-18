package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/cli"
	"crowdshield/internal/config"
	"crowdshield/internal/feed"
	lapimock "crowdshield/internal/lapi/mock"
	"crowdshield/internal/ops"
	"crowdshield/internal/state"
	"go.yaml.in/yaml/v3"
)

type operatorTestFetcher struct {
	result feed.FetchResult
	err    error
	calls  int
}

func (f *operatorTestFetcher) Fetch(context.Context, feed.FetchRequest) (feed.FetchResult, error) {
	f.calls++
	return f.result, f.err
}

type operatorSelectingFetcher struct {
	results map[string]feed.FetchResult
	errors  map[string]error
	calls   []string
}

func (f *operatorSelectingFetcher) Fetch(_ context.Context, request feed.FetchRequest) (feed.FetchResult, error) {
	f.calls = append(f.calls, request.URL)
	if err := f.errors[request.URL]; err != nil {
		return feed.FetchResult{}, err
	}
	return f.results[request.URL], nil
}

func TestValidateCLIConfigChecksCredentialsWithoutNetworkAccess(t *testing.T) {
	const passwordCanary = "validate-password-canary-do-not-emit"
	credentialPath := filepath.Join(t.TempDir(), "lapi.yaml")
	body := "url: https://unreachable.invalid\nlogin: crowdshield-test\npassword: " + passwordCanary + "\n"
	if err := os.WriteFile(credentialPath, []byte(body), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	cfg := config.Defaults("test")
	cfg.CrowdSec.CredentialsFile = credentialPath
	if err := ValidateCLIConfig(context.Background(), cfg); err != nil {
		t.Fatal("valid credential shape was rejected")
	}
}

func TestValidateCLIConfigRedactsCredentialFailure(t *testing.T) {
	const canary = "malformed-credential-canary-do-not-emit"
	credentialPath := filepath.Join(t.TempDir(), "lapi.yaml")
	if err := os.WriteFile(credentialPath, []byte("unknown: "+canary+"\n"), 0o600); err != nil {
		t.Fatal("write malformed credential fixture")
	}
	cfg := config.Defaults("test")
	cfg.CrowdSec.CredentialsFile = credentialPath
	err := ValidateCLIConfig(context.Background(), cfg)
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatal("malformed credential was accepted or exposed")
	}
}

func TestRunCLIStartsProductionRuntimeAndCancelsCleanly(t *testing.T) {
	const passwordCanary = "run-password-canary-do-not-emit"
	login := make(chan struct{}, 1)
	lapiServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/watchers/login" || request.Method != http.MethodPost {
			t.Error("run startup reached an unexpected LAPI route")
			http.NotFound(writer, request)
			return
		}
		login <- struct{}{}
		writer.Header().Set("Content-Type", "application/json")
		// #nosec G101 -- deliberate non-secret token fixture.
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"code": 200, "expire": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "token": "run-jwt-canary",
		})
	}))
	defer lapiServer.Close()

	temporary := t.TempDir()
	credentialPath := filepath.Join(temporary, "lapi.yaml")
	body := "url: " + lapiServer.URL + "\nlogin: test\npassword: " + passwordCanary + "\n"
	if err := os.WriteFile(credentialPath, []byte(body), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(temporary, "crowdshield.db")
	cfg.CrowdSec.CredentialsFile = credentialPath
	cfg.CrowdSec.AllowedHTTPHosts = []string{"127.0.0.1"}
	listenConfig := net.ListenConfig{}
	probe, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("reserve loopback port")
	}
	cfg.Server.ListenAddress = probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal("release loopback port")
	}
	cfg.Schedule.RunImmediately = false
	cfg.Schedule.StartupJitter = 0
	cfg.Schedule.Interval = config.Duration(time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- RunCLI(ctx, cfg, false, &output) }()
	select {
	case <-login:
		deadline := time.Now().Add(2 * time.Second)
		client := &http.Client{Timeout: 100 * time.Millisecond}
		for {
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.Server.ListenAddress+"/healthz", nil)
			if requestErr != nil {
				cancel()
				t.Fatal("construct health request")
			}
			response, err := client.Do(request)
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					break
				}
			}
			select {
			case runErr := <-done:
				cancel()
				t.Fatalf("run stopped before observability readiness: %v", runErr)
			default:
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("run did not serve its observability health endpoint")
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("run did not authenticate during startup")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("normal run cancellation returned a failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not complete ordered shutdown")
	}
	text := output.String()
	if strings.Contains(text, passwordCanary) || strings.Contains(text, "run-jwt-canary") || strings.Contains(text, lapiServer.URL) {
		t.Fatal("run output exposed a credential, token, or endpoint")
	}
}

func TestSyncCLIDryRunPlansWithoutStateOrLAPIMutation(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	lapiCalls := 0
	lapiServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		lapiCalls++
	}))
	defer lapiServer.Close()

	temporary := t.TempDir()
	credentialPath := filepath.Join(temporary, "lapi.yaml")
	credentialBody := "url: " + lapiServer.URL + "\nlogin: test\npassword: test-password\n"
	if err := os.WriteFile(credentialPath, []byte(credentialBody), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	databasePath := filepath.Join(temporary, "crowdshield.db")
	store, err := state.Open(context.Background(), state.Options{Path: databasePath, BusyTimeout: time.Second, IntegrityCheck: true})
	if err != nil {
		t.Fatal("initialize state fixture")
	}
	if err := store.Close(); err != nil {
		t.Fatal("close state fixture")
	}
	// #nosec G304 -- databasePath is created beneath this test's temporary directory.
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal("read state fixture before dry-run")
	}

	cfg := config.Defaults("test")
	cfg.Database.Path = databasePath
	cfg.CrowdSec.CredentialsFile = credentialPath
	cfg.CrowdSec.AllowedHTTPHosts = []string{"127.0.0.1"}
	configured := cfg.Feeds[2]
	configured.URL = "https://feed.invalid/list.netset"
	configured.ExpectedMinEntries = 1
	configured.ExpectedMaxEntries = 10
	configured.MaxGrowthRatio = 2
	configured.MaxShrinkRatio = 0.1
	cfg.Feeds = []config.FeedConfig{configured}
	fetcher := &operatorTestFetcher{result: feed.FetchResult{Body: []byte("8.8.8.0/24\n")}}

	result, err := syncCLIWithOptions(context.Background(), cfg, cli.SyncRequest{DryRun: true, Feed: configured.Name}, operatorSyncOptions{
		Now: func() time.Time { return now }, Fetcher: fetcher,
	})
	if err != nil || result.Outcome != ops.OutcomeSuccess || result.Counts.Added != 1 ||
		result.Counts.LAPIRequests != 0 || fetcher.calls != 1 || lapiCalls != 0 {
		t.Fatal("dry-run did not return the expected local aggregate plan")
	}
	// #nosec G304 -- databasePath is created beneath this test's temporary directory.
	after, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal("read state fixture after dry-run")
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run mutated the SQLite database")
	}
}

func TestSyncCLIDryRunUsesEmptyBaselineWithoutCreatingMissingDatabase(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	temporary := t.TempDir()
	credentialPath := filepath.Join(temporary, "lapi.yaml")
	if err := os.WriteFile(credentialPath, []byte("url: https://unreachable.invalid\nlogin: test\npassword: test-password\n"), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	databasePath := filepath.Join(temporary, "missing.db")
	cfg := config.Defaults("test")
	cfg.Database.Path = databasePath
	cfg.CrowdSec.CredentialsFile = credentialPath
	configured := cfg.Feeds[2]
	configured.URL = "https://feed.invalid/list.netset"
	configured.ExpectedMinEntries = 1
	configured.ExpectedMaxEntries = 10
	configured.MaxGrowthRatio = 2
	configured.MaxShrinkRatio = 0.1
	cfg.Feeds = []config.FeedConfig{configured}
	fetcher := &operatorTestFetcher{result: feed.FetchResult{Body: []byte("8.8.8.0/24\n")}}

	result, err := syncCLIWithOptions(context.Background(), cfg, cli.SyncRequest{DryRun: true}, operatorSyncOptions{
		Now: func() time.Time { return now }, Fetcher: fetcher,
	})
	if err != nil || result.Outcome != ops.OutcomeSuccess || result.Counts.Added != 1 {
		t.Fatal("dry-run did not use an empty baseline for a missing database")
	}
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatal("dry-run created the missing database")
	}
}

func TestSyncCLIEnforceAuthenticatesWritesOneOwnedDecisionAndHistory(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	lapiServer := lapimock.New(lapimock.Config{
		MachineID: "crowdshield-test", Password: "mock-password", Now: func() time.Time { return now },
	})
	defer lapiServer.Close()
	temporary := t.TempDir()
	credentialPath, err := lapiServer.WriteCredentials(temporary)
	if err != nil {
		t.Fatal("write mock LAPI credentials")
	}
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(temporary, "crowdshield.db")
	cfg.CrowdSec.CredentialsFile = credentialPath
	cfg.CrowdSec.AllowedHTTPHosts = []string{"127.0.0.1"}
	configured := cfg.Feeds[2]
	configured.URL = "https://feed.invalid/list.netset"
	configured.ExpectedMinEntries = 1
	configured.ExpectedMaxEntries = 10
	configured.MaxGrowthRatio = 2
	configured.MaxShrinkRatio = 0.1
	cfg.Feeds = []config.FeedConfig{configured}
	fetcher := &operatorTestFetcher{result: feed.FetchResult{Body: []byte("8.8.8.0/24\n")}}

	result, err := syncCLIWithOptions(context.Background(), cfg, cli.SyncRequest{Feed: configured.Name}, operatorSyncOptions{
		Now: func() time.Time { return now }, Fetcher: fetcher,
	})
	if err != nil || result.Outcome != ops.OutcomeSuccess || result.Counts.Added != 1 ||
		result.Counts.ActiveDecisions != 1 || fetcher.calls != 1 {
		t.Fatal("enforcing sync did not return the expected aggregate result")
	}
	if lapiServer.RequestCount(http.MethodPost, "/v1/watchers/login") != 1 ||
		lapiServer.RequestCount(http.MethodPost, "/v1/alerts") != 1 ||
		lapiServer.RequestCount(http.MethodGet, "/v1/alerts/1") != 1 {
		t.Fatal("enforcing sync did not use the expected authenticated ownership flow")
	}
	explanation, err := ExplainCLI(context.Background(), cfg, "8.8.8.8")
	if err != nil || explanation.Canonical != "8.8.8.8" || explanation.Kind != cli.ExplainIP ||
		explanation.Desired || !explanation.Covered || explanation.CoveringPrefix != "8.8.8.0/24" ||
		!explanation.Owned || explanation.OwnershipConflict || len(explanation.Contributors) != 1 ||
		explanation.Contributors[0] != configured.Name {
		t.Fatal("explain did not derive covered owned context from persisted state")
	}
	store, err := state.OpenReadOnly(context.Background(), state.Options{
		Path: cfg.Database.Path, BusyTimeout: time.Second, IntegrityCheck: true,
	})
	if err != nil {
		t.Fatal("open enforcing state read-only")
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error("store close failed")
		}
	}()
	runs, err := store.ListSyncRuns(context.Background(), 10)
	if err != nil || len(runs) != 1 || runs[0].Status != state.RunStatusSuccess {
		t.Fatal("enforcing sync history was not completed exactly once")
	}
	active, err := store.ListActiveDecisions(context.Background())
	if err != nil || len(active) != 1 {
		t.Fatal("enforcing sync did not persist exact owned decision state")
	}
}

func TestSyncCLIEnforceReturnsDegradedAggregateForPartialFeedFailure(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	lapiServer := lapimock.New(lapimock.Config{
		MachineID: "crowdshield-test", Password: "mock-password", Now: func() time.Time { return now },
	})
	defer lapiServer.Close()
	temporary := t.TempDir()
	credentialPath, err := lapiServer.WriteCredentials(temporary)
	if err != nil {
		t.Fatal("write mock LAPI credentials")
	}
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(temporary, "crowdshield.db")
	cfg.CrowdSec.CredentialsFile = credentialPath
	cfg.CrowdSec.AllowedHTTPHosts = []string{"127.0.0.1"}
	first := cfg.Feeds[2]
	first.Name = "feed-one"
	first.URL = "https://feed.invalid/one.netset"
	first.ExpectedMinEntries = 1
	first.ExpectedMaxEntries = 10
	first.MaxGrowthRatio = 2
	first.MaxShrinkRatio = 0.1
	second := first
	second.Name = "feed-two"
	second.URL = "https://feed.invalid/two.netset"
	cfg.Feeds = []config.FeedConfig{first, second}
	fetcher := &operatorSelectingFetcher{
		results: map[string]feed.FetchResult{first.URL: {Body: []byte("8.8.8.0/24\n")}},
		errors:  map[string]error{second.URL: &feed.Error{Category: feed.ErrRequest}},
	}

	result, err := syncCLIWithOptions(context.Background(), cfg, cli.SyncRequest{}, operatorSyncOptions{
		Now: func() time.Time { return now }, Fetcher: fetcher,
	})
	if err != nil || result.Outcome != ops.OutcomeDegraded || result.Failure != ops.FailureFeedDownload ||
		result.Counts.FeedsSucceeded != 1 || result.Counts.FeedsFailed != 1 || result.Counts.ActiveDecisions != 1 || len(fetcher.calls) != 2 {
		t.Fatal("partial feed failure did not return a bounded degraded aggregate")
	}
	feedStatuses, err := ListFeedsCLI(context.Background(), cfg)
	if err != nil || len(feedStatuses) != 2 || feedStatuses[0].Name != first.Name ||
		!feedStatuses[0].LastSuccess.Equal(now) || feedStatuses[0].ConsecutiveFailures != 0 ||
		feedStatuses[1].Name != second.Name || feedStatuses[1].ConsecutiveFailures != 1 ||
		feedStatuses[1].LastFailure != ops.FailureFeedDownload {
		t.Fatal("list-feeds did not map persisted success and failure health")
	}
}

func TestSyncCLIEnforceRecordsLAPIAuthFailureBeforeFeedFetch(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	lapiServer := lapimock.New(lapimock.Config{
		MachineID: "crowdshield-test", Password: "correct-password", Now: func() time.Time { return now },
	})
	defer lapiServer.Close()
	temporary := t.TempDir()
	credentialPath := filepath.Join(temporary, "lapi.yaml")
	credentialBody := "url: " + lapiServer.URL() + "\nlogin: crowdshield-test\npassword: wrong-password\n"
	if err := os.WriteFile(credentialPath, []byte(credentialBody), 0o600); err != nil {
		t.Fatal("write invalid credential fixture")
	}
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(temporary, "crowdshield.db")
	cfg.CrowdSec.CredentialsFile = credentialPath
	cfg.CrowdSec.AllowedHTTPHosts = []string{"127.0.0.1"}
	configured := cfg.Feeds[2]
	configured.URL = "https://feed.invalid/list.netset"
	configured.ExpectedMinEntries = 1
	configured.ExpectedMaxEntries = 10
	configured.MaxGrowthRatio = 2
	configured.MaxShrinkRatio = 0.1
	cfg.Feeds = []config.FeedConfig{configured}
	fetcher := &operatorTestFetcher{result: feed.FetchResult{Body: []byte("8.8.8.0/24\n")}}

	result, err := syncCLIWithOptions(context.Background(), cfg, cli.SyncRequest{}, operatorSyncOptions{
		Now: func() time.Time { return now }, Fetcher: fetcher,
	})
	if err != nil || result.Outcome != ops.OutcomeFailed || result.Failure != ops.FailureLAPIAuth ||
		fetcher.calls != 0 || result.Counts.ActiveDecisions != 0 || lapiServer.RequestCount(http.MethodPost, "/v1/watchers/login") != 1 {
		t.Fatal("LAPI authentication failure did not stop before feed processing")
	}
	store, err := state.OpenReadOnly(context.Background(), state.Options{
		Path: cfg.Database.Path, BusyTimeout: time.Second, IntegrityCheck: true,
	})
	if err != nil {
		t.Fatal("open failed-auth state read-only")
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error("store close failed")
		}
	}()
	runs, err := store.ListSyncRuns(context.Background(), 10)
	if err != nil || len(runs) != 1 || runs[0].Status != state.RunStatusFailed || runs[0].Failure != ops.FailureLAPIAuth {
		t.Fatal("LAPI authentication failure was not recorded with a bounded category")
	}
}

func TestSyncCLIEnforceClassifiesUnavailableLAPIWithoutFeedFetch(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	lapiServer := lapimock.New(lapimock.Config{
		MachineID: "crowdshield-test", Password: "mock-password", Now: func() time.Time { return now },
	})
	temporary := t.TempDir()
	credentialPath, err := lapiServer.WriteCredentials(temporary)
	if err != nil {
		t.Fatal("write mock LAPI credentials")
	}
	lapiServer.Close()
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(temporary, "crowdshield.db")
	cfg.CrowdSec.CredentialsFile = credentialPath
	cfg.CrowdSec.AllowedHTTPHosts = []string{"127.0.0.1"}
	configured := cfg.Feeds[2]
	configured.URL = "https://feed.invalid/list.netset"
	configured.ExpectedMinEntries = 1
	configured.ExpectedMaxEntries = 10
	configured.MaxGrowthRatio = 2
	configured.MaxShrinkRatio = 0.1
	cfg.Feeds = []config.FeedConfig{configured}
	fetcher := &operatorTestFetcher{result: feed.FetchResult{Body: []byte("8.8.8.0/24\n")}}

	result, err := syncCLIWithOptions(context.Background(), cfg, cli.SyncRequest{}, operatorSyncOptions{
		Now: func() time.Time { return now }, Fetcher: fetcher,
	})
	if err != nil || result.Outcome != ops.OutcomeFailed || result.Failure != ops.FailureLAPI || fetcher.calls != 0 {
		t.Fatal("unavailable LAPI did not return the bounded transport category before feed processing")
	}
}

func TestSyncCLIEnforceClassifiesUnavailableDatabaseWithoutExternalCalls(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	temporary := t.TempDir()
	credentialPath := filepath.Join(temporary, "lapi.yaml")
	if err := os.WriteFile(credentialPath, []byte("url: https://unreachable.invalid\nlogin: test\npassword: test-password\n"), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	databasePath := filepath.Join(temporary, "database-directory")
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatal("create unusable database path")
	}
	cfg := config.Defaults("test")
	cfg.Database.Path = databasePath
	cfg.CrowdSec.CredentialsFile = credentialPath
	fetcher := &operatorTestFetcher{result: feed.FetchResult{Body: []byte("8.8.8.0/24\n")}}

	result, err := syncCLIWithOptions(context.Background(), cfg, cli.SyncRequest{}, operatorSyncOptions{
		Now: func() time.Time { return now }, Fetcher: fetcher,
	})
	if err != nil || result.Outcome != ops.OutcomeFailed || result.Failure != ops.FailureDatabase || fetcher.calls != 0 {
		t.Fatal("unavailable database did not return the bounded state category")
	}
}

func TestRunCLIRunOnceDelegatesExactlyOneEnforcingSync(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	calls := 0
	syncAction := func(_ context.Context, _ config.Config, request cli.SyncRequest) (ops.Result, error) {
		calls++
		if request.DryRun || request.Feed != "" {
			t.Error("run-once did not request one complete enforcing sync")
		}
		return ops.Result{Outcome: ops.OutcomeSuccess, StartedAt: now, CompletedAt: now}, nil
	}
	var output bytes.Buffer
	if err := runCLIWithOptions(context.Background(), config.Defaults("test"), true, &output, operatorRunOptions{Sync: syncAction}); err != nil {
		t.Fatal("successful run-once returned a runtime failure")
	}
	if calls != 1 {
		t.Fatal("run-once did not execute exactly one synchronization")
	}
}

func TestStatusCLIReportsMissingDatabaseWithoutCreatingIt(t *testing.T) {
	temporary := t.TempDir()
	databasePath := filepath.Join(temporary, "missing.db")
	cfg := config.Defaults("test")
	cfg.Database.Path = databasePath

	status, err := statusCLIWithOptions(context.Background(), cfg, operatorStatusOptions{
		Now: func() time.Time { return time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil || status.Ready || status.Reason != cli.StatusDatabase {
		t.Fatal("missing state did not return database-unavailable status")
	}
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatal("status created the missing database")
	}
}

func TestStatusCLIReportsCurrentAndStalePersistedSync(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		age    time.Duration
		ready  bool
		reason cli.StatusReason
	}{
		{name: "current", age: time.Hour, ready: true, reason: cli.StatusReady},
		{name: "stale", age: 13 * time.Hour, reason: cli.StatusSyncStale},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.Defaults("test")
			cfg.Database.Path = filepath.Join(t.TempDir(), "crowdshield.db")
			store, err := state.Open(context.Background(), state.Options{
				Path: cfg.Database.Path, BusyTimeout: time.Second, IntegrityCheck: true,
			})
			if err != nil {
				t.Fatal("open status state fixture")
			}
			completedAt := now.Add(-test.age)
			startedAt := completedAt.Add(-time.Minute)
			runID, err := store.BeginSyncRun(context.Background(), state.SyncModeEnforce, "", startedAt)
			if err != nil {
				t.Fatal("begin status sync fixture")
			}
			if err := store.CompleteSyncRun(context.Background(), runID, ops.Result{
				Outcome: ops.OutcomeSuccess, StartedAt: startedAt, CompletedAt: completedAt,
			}); err != nil {
				t.Fatal("complete status sync fixture")
			}
			if err := store.Close(); err != nil {
				t.Fatal("close status state fixture")
			}

			status, err := statusCLIWithOptions(context.Background(), cfg, operatorStatusOptions{Now: func() time.Time { return now }})
			if err != nil || status.Ready != test.ready || status.Reason != test.reason ||
				status.LastOutcome != ops.OutcomeSuccess || !status.LastSafeSync.Equal(completedAt) {
				t.Fatal("status did not derive readiness from persisted state")
			}
		})
	}
}

func TestListFeedsCLIUsesConfiguredFeedsWithoutCreatingMissingDatabase(t *testing.T) {
	cfg := config.Defaults("test")
	databasePath := filepath.Join(t.TempDir(), "missing.db")
	cfg.Database.Path = databasePath

	feeds, err := ListFeedsCLI(context.Background(), cfg)
	if err != nil || len(feeds) != len(cfg.Feeds) {
		t.Fatal("list-feeds did not return configured feeds before first state creation")
	}
	for index, configured := range cfg.Feeds {
		if feeds[index].Name != configured.Name || feeds[index].Enabled != configured.Enabled ||
			!feeds[index].LastSuccess.IsZero() || feeds[index].ConsecutiveFailures != 0 || feeds[index].LastFailure != "" {
			t.Fatal("list-feeds returned unexpected health for a missing database")
		}
	}
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatal("list-feeds created the missing database")
	}
}

func TestExplainCLIUsesCanonicalConfigPolicyWithoutCreatingMissingDatabase(t *testing.T) {
	cfg := config.Defaults("test")
	databasePath := filepath.Join(t.TempDir(), "missing.db")
	cfg.Database.Path = databasePath
	var allowed config.CIDR
	if err := yaml.Unmarshal([]byte("10.0.0.0/8\n"), &allowed); err != nil {
		t.Fatal("parse allowlist fixture")
	}
	cfg.Allowlists.CIDRs = []config.CIDR{allowed}

	result, err := ExplainCLI(context.Background(), cfg, "10.1.2.3/8")
	if err != nil || result.Canonical != "10.0.0.0/8" || result.Kind != cli.ExplainRange ||
		!result.Allowlisted || result.Desired || result.Covered || result.Owned || result.OwnershipConflict || len(result.Contributors) != 0 {
		t.Fatal("explain did not return canonical config-only policy")
	}
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatal("explain created the missing database")
	}
}

func TestPruneCLIPlansWithoutMutationThenAppliesExactCounts(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(context.Background(), state.Options{
		Path: cfg.Database.Path, BusyTimeout: time.Second, IntegrityCheck: true,
	})
	if err != nil {
		t.Fatal("open prune fixture")
	}
	started := now.Add(-60 * 24 * time.Hour)
	runID, err := store.BeginSyncRun(context.Background(), state.SyncModeEnforce, "", started)
	if err != nil {
		t.Fatal("begin prune fixture")
	}
	if err := store.CompleteSyncRun(context.Background(), runID, ops.Result{
		Outcome: ops.OutcomeSuccess, StartedAt: started, CompletedAt: started.Add(time.Minute),
	}); err != nil || store.Close() != nil {
		t.Fatal("complete prune fixture")
	}
	before, err := os.ReadFile(cfg.Database.Path)
	if err != nil {
		t.Fatal("read prune fixture")
	}

	planned, err := pruneCLIWithOptions(context.Background(), cfg, false, operatorPruneOptions{Now: func() time.Time { return now }})
	if err != nil || planned.SyncRuns != 1 || planned.OwnershipConflicts != 0 {
		t.Fatal("prune plan did not report exact eligible history")
	}
	afterPlan, err := os.ReadFile(cfg.Database.Path)
	if err != nil || !bytes.Equal(before, afterPlan) {
		t.Fatal("prune plan mutated the database")
	}
	applied, err := pruneCLIWithOptions(context.Background(), cfg, true, operatorPruneOptions{Now: func() time.Time { return now }})
	if err != nil || applied != planned {
		t.Fatal("confirmed prune did not apply the exact plan")
	}
	readStore, err := state.OpenReadOnly(context.Background(), state.Options{
		Path: cfg.Database.Path, BusyTimeout: time.Second, IntegrityCheck: true,
	})
	if err != nil {
		t.Fatal("reopen pruned state")
	}
	defer func() {
		if err := readStore.Close(); err != nil {
			t.Error("read-only store close failed")
		}
	}()
	runs, err := readStore.ListSyncRuns(context.Background(), 10)
	if err != nil || len(runs) != 0 {
		t.Fatal("confirmed prune left eligible history")
	}
}

func TestDBCheckCLIIsReadOnlyAndDoesNotCreateMissingState(t *testing.T) {
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(t.TempDir(), "state.db")
	cfg.Database.IntegrityCheckOnStart = false
	store, err := state.Open(context.Background(), state.Options{
		Path: cfg.Database.Path, BusyTimeout: time.Second, IntegrityCheck: true,
	})
	if err != nil || store.Close() != nil {
		t.Fatal("initialize database-check fixture")
	}
	before, err := os.ReadFile(cfg.Database.Path)
	if err != nil {
		t.Fatal("read database-check fixture")
	}
	if err := DBCheckCLI(context.Background(), cfg); err != nil {
		t.Fatal("database check rejected valid state")
	}
	after, err := os.ReadFile(cfg.Database.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("database check mutated valid state")
	}

	missingPath := filepath.Join(t.TempDir(), "db-path-canary-do-not-emit.db")
	cfg.Database.Path = missingPath
	err = DBCheckCLI(context.Background(), cfg)
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("database check did not return a fixed missing-state failure")
	}
	if _, statErr := os.Stat(missingPath); !os.IsNotExist(statErr) {
		t.Fatal("database check created missing state")
	}
}
