package mock

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdshield/internal/credentials"
	"crowdshield/internal/lapi"
)

func newClient(t *testing.T, server *Server, now func() time.Time) *lapi.Client {
	t.Helper()
	path, err := server.WriteCredentials(t.TempDir())
	if err != nil {
		t.Fatal("unable to write mock credentials")
	}
	creds, err := (credentials.Loader{MaxBytes: credentials.DefaultMaxBytes, StrictPermissions: true, AllowedHTTPHosts: []string{"127.0.0.1"}}).Load(path)
	if err != nil {
		t.Fatal("unable to load mock credentials")
	}
	t.Cleanup(creds.Destroy)
	client, err := lapi.New(lapi.Options{
		Credentials: creds, UserAgent: "crowdshield/test", RequestTimeout: time.Second,
		ConnectTimeout: time.Second, MaxResponseBytes: 64 << 10, AuthRefreshBefore: time.Minute,
		HTTPClient: server.Client(), Now: now,
	})
	if err != nil {
		t.Fatal("unable to create client")
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestHandlerCanBeServedByExternalListener(t *testing.T) {
	handler := NewHandler(Config{MachineID: "crowdshield-test", Password: "mock-password"})
	server := httptest.NewServer(handler)
	defer server.Close()

	body := bytes.NewBufferString(`{"machine_id":"crowdshield-test","password":"mock-password"}`)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/watchers/login", body)
	if err != nil {
		t.Fatal("unable to create login request")
	}
	request.Header.Set("User-Agent", "crowdshield/test")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("external listener request failed")
	}
	defer func() { _ = response.Body.Close() }()
	var result struct {
		Token string `json:"token"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil || result.Token == "" {
		t.Fatal("external listener did not serve the mock handler")
	}
}

func TestServerModelsDuplicateCreationExactReadsAndExpiration(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	server := New(Config{MachineID: "crowdshield-test", Password: "mock-password", Now: func() time.Time { return now }})
	defer server.Close()
	client := newClient(t, server, func() time.Time { return now })
	request := lapi.CreateRequest{
		FeedName:       "feed-one",
		OperationToken: "0123456789abcdef0123456789abcdef", // gitleaks:allow -- fixed synthetic idempotency token
		Duration:       25 * time.Hour,
		Decisions:      []lapi.DecisionInput{{Scope: "Range", Value: "8.8.8.0/24"}},
	}
	firstID, err := client.CreateAlert(context.Background(), request)
	if err != nil {
		t.Fatal("first create failed")
	}
	request.OperationToken = "abcdef0123456789abcdef0123456789" // gitleaks:allow -- fixed synthetic idempotency token
	secondID, err := client.CreateAlert(context.Background(), request)
	if err != nil || secondID == firstID || len(server.Alerts()) != 2 {
		t.Fatal("mock incorrectly deduplicated decisions")
	}
	first, err := client.GetAlert(context.Background(), firstID)
	if err != nil || len(first.Decisions) != 1 || first.MachineID != "crowdshield-test" {
		t.Fatal("exact alert read failed")
	}
	foreign := lapi.Alert{ID: 900, MachineID: "foreign", Scenario: "foreign/scenario", Decisions: []lapi.Decision{{ID: 901, Origin: "foreign", Scope: "Ip", Value: "9.9.9.9"}}}
	server.AddForeignAlert(foreign)
	if err := client.ExpireDecision(context.Background(), first.Decisions[0].ID); err != nil || !server.WasExpired(first.Decisions[0].ID) || server.WasExpired(901) {
		t.Fatal("exact decision expiration semantics changed")
	}
}

func TestServerExercisesTokenExpiryAndUnauthorizedRetry(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	server := New(Config{TokenTTL: 10 * time.Minute, Now: func() time.Time { return now }})
	defer server.Close()
	client := newClient(t, server, func() time.Time { return now })
	server.AddForeignAlert(lapi.Alert{ID: 1, Scenario: "foreign/scenario"})
	if _, err := client.GetAlert(context.Background(), 1); err != nil {
		t.Fatal("initial read failed")
	}
	server.ForceUnauthorizedOnce()
	if _, err := client.GetAlert(context.Background(), 1); err != nil {
		t.Fatal("one unauthorized response was not recovered")
	}
	now = now.Add(10 * time.Minute)
	if _, err := client.GetAlert(context.Background(), 1); err != nil {
		t.Fatal("expired token was not refreshed")
	}
	if server.RequestCount("POST", "/v1/watchers/login") < 3 {
		t.Fatal("mock did not exercise expected token refreshes")
	}
}
