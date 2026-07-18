package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crowdshield/internal/credentials"
)

const lapiPasswordCanary = "lapi-password-canary-do-not-emit"

func loadTestCredentials(t *testing.T, endpoint string) *credentials.Credentials {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lapi.yaml")
	body := "url: " + endpoint + "\nlogin: crowdshield-test\npassword: " + lapiPasswordCanary + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal("unable to write credential fixture")
	}
	creds, err := (credentials.Loader{MaxBytes: credentials.DefaultMaxBytes, StrictPermissions: true, AllowedHTTPHosts: []string{"127.0.0.1"}}).Load(path)
	if err != nil {
		t.Fatal("unable to load credential fixture")
	}
	t.Cleanup(creds.Destroy)
	return creds
}

func testOptions(t *testing.T, server *httptest.Server, now func() time.Time) Options {
	t.Helper()
	return Options{
		Credentials:       loadTestCredentials(t, server.URL),
		UserAgent:         "crowdshield/test",
		RequestTimeout:    time.Second,
		ConnectTimeout:    time.Second,
		MaxResponseBytes:  64 << 10,
		AuthRefreshBefore: 5 * time.Minute,
		HTTPClient:        server.Client(),
		Now:               now,
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatal("unable to encode mock response")
	}
}

func TestClientAuthenticateCachesBoundedToken(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	var logins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/watchers/login" || request.Method != http.MethodPost {
			t.Error("startup authentication used an unexpected LAPI route")
			http.NotFound(writer, request)
			return
		}
		logins.Add(1)
		writeJSON(t, writer, http.StatusOK, map[string]any{
			"code": 200, "expire": now.Add(time.Hour).Format(time.RFC3339), "token": "startup-jwt-canary",
		})
	}))
	defer server.Close()
	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct LAPI client")
	}
	defer client.CloseIdleConnections()
	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatal("explicit startup authentication failed")
	}
	if err := client.Authenticate(context.Background()); err != nil || logins.Load() != 1 {
		t.Fatal("valid startup token was not reused")
	}
}

func TestClientCreateVerifyAndExpireContract(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	var logins, creates, gets, deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != "crowdshield/test" {
			t.Error("bounded user agent missing")
		}
		switch {
		case request.URL.Path == "/v1/watchers/login" && request.Method == http.MethodPost:
			logins.Add(1)
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["machine_id"] != "crowdshield-test" || body["password"] != lapiPasswordCanary {
				t.Error("login wire contract changed")
			}
			writeJSON(t, writer, http.StatusOK, map[string]any{"code": 200, "expire": now.Add(time.Hour).Format(time.RFC3339), "token": "jwt-canary"})
		case request.URL.Path == "/v1/alerts" && request.Method == http.MethodPost:
			creates.Add(1)
			if request.Header.Get("Authorization") != "Bearer jwt-canary" {
				t.Error("bearer token missing")
			}
			var alerts []wireAlert
			if err := json.NewDecoder(request.Body).Decode(&alerts); err != nil || len(alerts) != 1 {
				t.Error("alert batch shape changed")
				writeJSON(t, writer, http.StatusBadRequest, map[string]string{"message": "bad"})
				return
			}
			alert := alerts[0]
			if alert.Scenario != "crowdshield/feed-one" || alert.ScenarioHash != "crowdshield:0123456789abcdef0123456789abcdef" || alert.ScenarioVersion != "1.0" || alert.Message != "External threat feed: feed-one" {
				t.Error("ownership or attribution fields changed")
			}
			if alert.EventsCount != 1 || len(alert.Events) != 1 || alert.Capacity != 2 || alert.Leakspeed != "0" || alert.Source.Scope != "service" || alert.Source.Value != "crowdshield" || alert.Simulated {
				t.Error("required Alert fields missing")
			}
			if len(alert.Decisions) != 2 || alert.Decisions[0].Origin != "crowdshield" || alert.Decisions[0].Type != "ban" || alert.Decisions[0].Scenario != alert.Scenario {
				t.Error("decision contract changed")
			}
			writeJSON(t, writer, http.StatusCreated, []string{"42"})
		case request.URL.Path == "/v1/alerts/42" && request.Method == http.MethodGet:
			gets.Add(1)
			writeJSON(t, writer, http.StatusOK, Alert{
				ID: 42, MachineID: "crowdshield-test", Scenario: "crowdshield/feed-one", ScenarioHash: "crowdshield:0123456789abcdef0123456789abcdef",
				Decisions: []Decision{
					{ID: 101, Origin: "crowdshield", Type: "ban", Scope: "Range", Value: "8.8.8.0/24", Duration: "25h", Scenario: "crowdshield/feed-one"},
					{ID: 102, Origin: "crowdshield", Type: "ban", Scope: "Ip", Value: "9.9.9.9", Duration: "25h", Scenario: "crowdshield/feed-one"},
				},
			})
		case request.URL.Path == "/v1/decisions/101" && request.Method == http.MethodDelete:
			deletes.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"message":"decision expired"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct LAPI client")
	}
	defer client.CloseIdleConnections()
	alertID, err := client.CreateAlert(context.Background(), CreateRequest{
		FeedName:       "feed-one",
		OperationToken: "0123456789abcdef0123456789abcdef",
		Duration:       25 * time.Hour,
		Decisions: []DecisionInput{
			{Scope: "Range", Value: "8.8.8.0/24"},
			{Scope: "Ip", Value: "9.9.9.9"},
		},
	})
	if err != nil || alertID != 42 {
		t.Fatal("create alert failed")
	}
	alert, err := client.GetAlert(context.Background(), alertID)
	if err != nil || alert.ID != 42 || len(alert.Decisions) != 2 {
		t.Fatal("exact alert verification failed")
	}
	if err := client.ExpireDecision(context.Background(), 101); err != nil {
		t.Fatal("exact decision expiration failed")
	}
	if logins.Load() != 1 || creates.Load() != 1 || gets.Load() != 1 || deletes.Load() != 1 {
		t.Fatal("unexpected LAPI request count")
	}
}

func TestClientRefreshesTokenBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	var logins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			index := logins.Add(1)
			writeJSON(t, writer, http.StatusOK, map[string]any{"expire": now.Add(10 * time.Minute).Format(time.RFC3339), "token": fmt.Sprintf("token-%d", index)})
			return
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer token-") {
			t.Error("token missing")
		}
		writeJSON(t, writer, http.StatusOK, Alert{ID: 1, Scenario: "crowdshield/feed-one"})
	}))
	defer server.Close()
	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct client")
	}
	if _, err := client.GetAlert(context.Background(), 1); err != nil {
		t.Fatal("initial request failed")
	}
	now = now.Add(6 * time.Minute)
	if _, err := client.GetAlert(context.Background(), 1); err != nil {
		t.Fatal("refresh request failed")
	}
	if logins.Load() != 2 {
		t.Fatal("token was not refreshed before expiry")
	}
}

func TestClientRetriesOneUnauthorizedAfterRelogin(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	var logins, reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			index := logins.Add(1)
			writeJSON(t, writer, http.StatusOK, map[string]any{"expire": now.Add(time.Hour).Format(time.RFC3339), "token": fmt.Sprintf("token-%d", index)})
			return
		}
		if reads.Add(1) == 1 {
			writeJSON(t, writer, http.StatusUnauthorized, map[string]string{"message": "expired"})
			return
		}
		writeJSON(t, writer, http.StatusOK, Alert{ID: 1, Scenario: "crowdshield/feed-one"})
	}))
	defer server.Close()
	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct client")
	}
	if _, err := client.GetAlert(context.Background(), 1); err != nil {
		t.Fatal("401 reauthentication failed")
	}
	if logins.Load() != 2 || reads.Load() != 2 {
		t.Fatal("401 retry count was not exactly one")
	}
}

func TestClientBoundsAndSanitizesResponses(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		handler  func(http.ResponseWriter, *http.Request)
		category ErrorCategory
	}{
		{name: "oversized", category: ErrResponseSize, handler: func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/v1/watchers/login" {
				writeJSON(t, writer, http.StatusOK, map[string]any{"expire": now.Add(time.Hour).Format(time.RFC3339), "token": "token"})
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(strings.Repeat("x", 2048)))
		}},
		{name: "malformed", category: ErrDecode, handler: func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/v1/watchers/login" {
				writeJSON(t, writer, http.StatusOK, map[string]any{"expire": now.Add(time.Hour).Format(time.RFC3339), "token": "token"})
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"password":"` + lapiPasswordCanary))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tc.handler))
			defer server.Close()
			options := testOptions(t, server, func() time.Time { return now })
			options.MaxResponseBytes = 1024
			client, err := New(options)
			if err != nil {
				t.Fatal("unable to construct client")
			}
			_, err = client.GetAlert(context.Background(), 1)
			if err == nil || !IsCategory(err, tc.category) || strings.Contains(err.Error(), lapiPasswordCanary) {
				t.Fatal("unsafe response was not bounded and sanitized")
			}
		})
	}
}

func TestClientRejectsInvalidOwnershipInputsBeforeNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid request reached network")
	}))
	defer server.Close()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct client")
	}
	invalid := []CreateRequest{
		{},
		{FeedName: "bad/feed", OperationToken: strings.Repeat("a", 32), Duration: time.Hour, Decisions: []DecisionInput{{Scope: "Ip", Value: "9.9.9.9"}}},
		{FeedName: "feed-one", OperationToken: "short", Duration: time.Hour, Decisions: []DecisionInput{{Scope: "Ip", Value: "9.9.9.9"}}},
		{FeedName: "feed-one", OperationToken: strings.Repeat("a", 32), Duration: 0, Decisions: []DecisionInput{{Scope: "Ip", Value: "9.9.9.9"}}},
		{FeedName: "feed-one", OperationToken: strings.Repeat("a", 32), Duration: time.Hour, Decisions: []DecisionInput{{Scope: "Ip", Value: "8.8.8.0/24"}}},
	}
	for range invalid {
	}
	for _, request := range invalid {
		if _, err := client.CreateAlert(context.Background(), request); err == nil || !IsCategory(err, ErrContract) {
			t.Fatal("invalid ownership input accepted")
		}
	}
}

func TestFindOperationFiltersScenarioHashLocally(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			writeJSON(t, writer, http.StatusOK, map[string]any{"expire": now.Add(time.Hour).Format(time.RFC3339), "token": "token"})
			return
		}
		if request.URL.Query().Get("scenario") != "crowdshield/feed-one" || request.URL.Query().Get("limit") != "100" {
			t.Error("bounded recovery query missing")
		}
		writeJSON(t, writer, http.StatusOK, []Alert{
			{ID: 1, Scenario: "crowdshield/feed-one", ScenarioHash: "crowdshield:other"},
			{ID: 2, Scenario: "crowdshield/feed-one", ScenarioHash: "crowdshield:0123456789abcdef0123456789abcdef"},
		})
	}))
	defer server.Close()
	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct client")
	}
	alert, found, err := client.FindOperation(context.Background(), "feed-one", "0123456789abcdef0123456789abcdef")
	if err != nil || !found || alert.ID != 2 {
		t.Fatal("operation recovery lookup failed")
	}
}

func TestClientFormattingDoesNotExposeTokenOrCredential(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(t, writer, http.StatusOK, map[string]any{"expire": now.Add(time.Hour).Format(time.RFC3339), "token": "jwt-token-canary"})
	}))
	defer server.Close()
	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct client")
	}
	_ = client.ensureToken(context.Background(), false)
	for _, rendered := range []string{fmt.Sprint(client), fmt.Sprintf("%+v", client), fmt.Sprintf("%#v", client)} {
		if strings.Contains(rendered, "jwt-token-canary") || strings.Contains(rendered, lapiPasswordCanary) {
			t.Fatal("client formatting exposed authentication material")
		}
	}
}

func TestExactIDsMustBePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	now := time.Now()
	client, err := New(testOptions(t, server, func() time.Time { return now }))
	if err != nil {
		t.Fatal("unable to construct client")
	}
	for _, value := range []int64{0, -1} {
		if _, err := client.GetAlert(context.Background(), value); err == nil {
			t.Fatal("non-positive alert ID accepted")
		}
		if err := client.ExpireDecision(context.Background(), value); err == nil {
			t.Fatal("non-positive decision ID accepted")
		}
	}
}

func TestCreateResponseRequiresOneNumericID(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	for _, responseBody := range [][]string{{}, {"1", "2"}, {"not-a-number"}, {strconv.FormatInt(0, 10)}} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/v1/watchers/login" {
				writeJSON(t, writer, http.StatusOK, map[string]any{"expire": now.Add(time.Hour).Format(time.RFC3339), "token": "token"})
				return
			}
			writeJSON(t, writer, http.StatusCreated, responseBody)
		}))
		client, err := New(testOptions(t, server, func() time.Time { return now }))
		if err != nil {
			server.Close()
			t.Fatal("unable to construct client")
		}
		_, err = client.CreateAlert(context.Background(), CreateRequest{
			FeedName: "feed-one", OperationToken: strings.Repeat("a", 32), Duration: time.Hour,
			Decisions: []DecisionInput{{Scope: "Ip", Value: "9.9.9.9"}},
		})
		server.Close()
		if err == nil || !IsCategory(err, ErrContract) {
			t.Fatal("invalid create response accepted")
		}
	}
}
