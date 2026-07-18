package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/config"
	"crowdshield/internal/ops"
)

func failureNotice(now time.Time) Notice {
	return Notice{
		Kind: KindRepeatedFailure, Severity: ops.SeverityWarning,
		Feed: "feed-one", Failure: ops.FailureLAPI, ConsecutiveFailures: 3,
		At: now,
	}
}

type closeTrackingTransport struct{ closed bool }

func (t *closeTrackingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not used")
}

func (t *closeTrackingTransport) CloseIdleConnections() { t.closed = true }

func TestHTTPTransportClosesOwnedIdleConnections(t *testing.T) {
	tracking := &closeTrackingTransport{}
	transport := &HTTPTransport{client: &http.Client{Transport: tracking}}
	transport.CloseIdleConnections()
	if !tracking.closed {
		t.Fatal("notification HTTP transport did not close its idle connections")
	}
}

func TestHTTPTransportSendsBoundedNtfyRequestWithoutURLTokenOrIndicators(t *testing.T) {
	const token = "token-canary-do-not-emit"
	requestSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/alerts" || request.URL.RawQuery != "" || request.URL.User != nil {
			t.Error("notification request put metadata or credentials in its URL")
		}
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Error("notification token was not sent as bearer authorization")
		}
		if request.Header.Get("Title") == "" || request.Header.Get("Priority") == "" {
			t.Error("bounded ntfy headers were missing")
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 2049))
		if err != nil || len(body) == 0 || len(body) > 2048 {
			t.Error("notification body was empty or unbounded")
		}
		text := string(body)
		if strings.Contains(text, token) || strings.Contains(text, "198.51.100.23") || strings.Contains(text, "2001:db8::23") || strings.Contains(text, "https://") {
			t.Error("notification body exposed a privacy canary")
		}
		requestSeen <- struct{}{}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	transport, err := NewHTTPTransport(HTTPOptions{
		ServerURL: server.URL, Topic: "alerts", Token: config.NewSecret(token),
		Timeout: time.Second, AllowHTTP: true,
	})
	if err != nil {
		t.Fatal("valid local ntfy transport rejected")
	}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if err := transport.Send(context.Background(), failureNotice(now)); err != nil {
		t.Fatal("valid notification failed")
	}
	select {
	case <-requestSeen:
	case <-time.After(time.Second):
		t.Fatal("notification request was not observed")
	}
}

func TestHTTPTransportUsesNormalTLSVerificationAndFixedErrors(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	transport, err := NewHTTPTransport(HTTPOptions{
		ServerURL: tlsServer.URL, Topic: "alerts", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal("valid HTTPS transport rejected")
	}
	err = transport.Send(context.Background(), failureNotice(time.Now()))
	if !errors.Is(err, ErrTransport) || err.Error() != ErrTransport.Error() {
		t.Fatal("TLS verification failure was not reduced to a fixed category")
	}

	responseServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = writer.Write([]byte("198.51.100.23 password-canary response body"))
	}))
	defer responseServer.Close()
	transport, err = NewHTTPTransport(HTTPOptions{
		ServerURL: responseServer.URL, Topic: "alerts", Timeout: time.Second, AllowHTTP: true,
	})
	if err != nil {
		t.Fatal("valid response-test transport rejected")
	}
	err = transport.Send(context.Background(), failureNotice(time.Now()))
	if !errors.Is(err, ErrResponse) || err.Error() != ErrResponse.Error() || strings.Contains(err.Error(), responseServer.URL) {
		t.Fatal("ntfy response failure exposed arbitrary response or URL data")
	}
}

func TestNoticeValidationRejectsIndicatorAndUnboundedFields(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	for _, feed := range []string{"198.51.100.23", "2001:db8::23", "198.51.100.0/24", "https://feed.example.invalid/private"} {
		notice := failureNotice(now)
		notice.Feed = feed
		if err := notice.Validate(); err == nil {
			t.Fatal("indicator-bearing notification field accepted")
		}
	}
	invalid := []Notice{
		{},
		{Kind: KindRepeatedFailure, Severity: ops.SeverityWarning, Failure: ops.FailureLAPI, ConsecutiveFailures: 0, At: now},
		{Kind: KindRecovery, Severity: ops.SeverityInfo, At: now},
		{Kind: KindSuspiciousChange, Severity: ops.SeverityWarning, At: now},
		{Kind: KindStartup, Severity: ops.SeverityInfo, Feed: "feed-one", At: now},
	}
	for _, notice := range invalid {
		if err := notice.Validate(); err == nil {
			t.Fatal("invalid bounded notice accepted")
		}
	}
}
