package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
)

func TestHealthcheckDoesNotLoadConfigurationAndAcceptsLiveEndpoint(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/healthz" {
			t.Error("healthcheck sent an unexpected request")
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("{\"status\":\"alive\"}\n"))
	}))
	defer server.Close()

	loads := 0
	options := Options{
		Version: buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) {
			loads++
			return config.Config{}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"healthcheck", "--url", server.URL + "/healthz", "--timeout", "1s",
	}, &stdout, &stderr, options)
	if code != ExitSuccess || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected healthcheck result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if loads != 0 {
		t.Fatal("healthcheck loaded the main configuration")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("healthcheck made %d requests; want exactly one", got)
	}
}

func TestHealthcheckRejectsUnsafeTargetsAsUsage(t *testing.T) {
	targets := []string{
		"https://127.0.0.1:9090/healthz",
		"http://localhost:9090/healthz",
		"http://192.0.2.1:9090/healthz",
		"http://127.0.0.1:9090/readyz",
		"http://user@127.0.0.1:9090/healthz",
		"http://127.0.0.1:9090/healthz?full=true",
		"http://127.0.0.1/healthz",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(context.Background(), []string{"healthcheck", "--url", target}, &stdout, &stderr, Options{})
			if code != ExitUsage || stdout.Len() != 0 || stderr.String() != Usage+"\n" {
				t.Fatal("unsafe healthcheck target did not fail as fixed usage")
			}
		})
	}
}

func TestHealthcheckRejectsUnexpectedResponsesWithFixedOutput(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		location    string
	}{
		{name: "status", status: http.StatusServiceUnavailable, contentType: "application/json", body: "{\"status\":\"alive\"}\n"},
		{name: "content type", status: http.StatusOK, contentType: "text/plain", body: "{\"status\":\"alive\"}\n"},
		{name: "wrong status body", status: http.StatusOK, contentType: "application/json", body: "{\"status\":\"ready\"}\n"},
		{name: "unknown field", status: http.StatusOK, contentType: "application/json", body: "{\"status\":\"alive\",\"detail\":\"private\"}\n"},
		{name: "multiple values", status: http.StatusOK, contentType: "application/json", body: "{\"status\":\"alive\"}\n{}\n"},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: strings.Repeat("x", int(maxHealthcheckBodyBytes)+1)},
		{name: "redirect", status: http.StatusTemporaryRedirect, contentType: "application/json", body: "{}\n", location: "http://127.0.0.1:1/healthz"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				writer.Header().Set("Content-Type", test.contentType)
				if test.location != "" {
					writer.Header().Set("Location", test.location)
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()

			var stdout, stderr bytes.Buffer
			code := Execute(context.Background(), []string{"healthcheck", "--url", server.URL + "/healthz"}, &stdout, &stderr, Options{})
			if code != ExitOperational || stdout.Len() != 0 || stderr.String() != "healthcheck failed\n" {
				t.Fatal("unexpected response did not produce a fixed operational failure")
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("healthcheck followed or retried a request: got %d", got)
			}
		})
	}
}

func TestHealthcheckTimeoutIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte("{\"status\":\"alive\"}\n"))
	}))
	defer server.Close()

	started := time.Now()
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{
		"healthcheck", "--url", server.URL + "/healthz", "--timeout", "20ms",
	}, &stdout, &stderr, Options{})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatal("healthcheck exceeded its timeout bound")
	}
	if code != ExitOperational || stdout.Len() != 0 || stderr.String() != "healthcheck failed\n" {
		t.Fatal("timeout did not produce a fixed operational failure")
	}
}

func TestHealthcheckDefaultsAreStableAndShort(t *testing.T) {
	if defaultHealthcheckURL != "http://127.0.0.1:9090/healthz" {
		t.Fatal("healthcheck default URL changed")
	}
	if defaultHealthcheckTimeout != 2*time.Second || defaultHealthcheckTimeout > maxHealthcheckTimeout {
		t.Fatal("healthcheck default timeout is not the documented short bound")
	}
}
