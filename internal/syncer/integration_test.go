package syncer

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/credentials"
	"crowdshield/internal/feed"
	"crowdshield/internal/lapi"
	lapimock "crowdshield/internal/lapi/mock"
	"crowdshield/internal/reconcile"
)

func TestVerticalFeedToCrowdSecReconciliation(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	cfg.Decisions.MissingGraceRuns = 1
	store := openSyncStore(t)
	server := lapimock.New(lapimock.Config{MachineID: "crowdshield-test", Password: "mock-password", Now: func() time.Time { return now }})
	t.Cleanup(server.Close)
	credentialPath, err := server.WriteCredentials(t.TempDir())
	if err != nil {
		t.Fatal("unable to write mock credentials")
	}
	creds, err := (credentials.Loader{
		MaxBytes: credentials.DefaultMaxBytes, StrictPermissions: true, AllowedHTTPHosts: []string{"127.0.0.1"},
	}).Load(credentialPath)
	if err != nil {
		t.Fatal("unable to load mock credentials")
	}
	t.Cleanup(creds.Destroy)
	client, err := lapi.New(lapi.Options{
		Credentials: creds, UserAgent: "crowdshield/test", RequestTimeout: time.Second,
		ConnectTimeout: time.Second, MaxResponseBytes: 1 << 20, AuthRefreshBefore: time.Minute,
		HTTPClient: server.Client(), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal("unable to construct LAPI client")
	}
	t.Cleanup(client.CloseIdleConnections)
	tokenIndex := 0
	reconciler, err := reconcile.New(reconcile.Options{
		Store: store, LAPI: client, MachineID: "crowdshield-test", Duration: 25 * time.Hour,
		RefreshBefore: 12 * time.Hour, BatchSize: 100, Now: func() time.Time { return now },
		Token: func() (string, error) {
			tokenIndex++
			return strings.Repeat(strconv.Itoa(tokenIndex), 32), nil
		},
	})
	if err != nil {
		t.Fatal("unable to construct reconciler")
	}
	fetcher := &fakeFetcher{results: map[string]feed.FetchResult{
		cfg.Feeds[0].URL: {Body: []byte("8.8.8.0/24\n9.9.9.0/24\n")},
	}, errors: map[string]error{}}
	engine, err := New(Options{Config: cfg, Store: store, Fetcher: fetcher, Reconciler: reconciler, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal("unable to construct sync engine")
	}
	first, err := engine.Run(context.Background(), RunOptions{})
	if err != nil || first.Reconcile.Added != 2 {
		t.Fatal("initial vertical reconciliation failed")
	}
	alerts := server.Alerts()
	if len(alerts) != 1 || len(alerts[0].Decisions) != 2 {
		t.Fatal("initial CrowdSec decisions were incorrect")
	}
	var removedDecisionID int64
	for _, decision := range alerts[0].Decisions {
		if decision.Value == "9.9.9.0/24" {
			removedDecisionID = decision.ID
		}
	}
	if removedDecisionID == 0 {
		t.Fatal("removal fixture decision missing")
	}
	now = now.Add(time.Hour)
	fetcher.results[cfg.Feeds[0].URL] = feed.FetchResult{Body: []byte("8.8.8.0/24\n")}
	second, err := engine.Run(context.Background(), RunOptions{})
	if err != nil || second.Reconcile.Removed != 1 || !server.WasExpired(removedDecisionID) {
		t.Fatal("successful missing-grace expiration failed")
	}
	active, err := store.ListActiveDecisions(context.Background())
	if err != nil || len(active) != 1 || active[0].Value != "8.8.8.0/24" {
		t.Fatal("owned-decision state did not converge")
	}
}
