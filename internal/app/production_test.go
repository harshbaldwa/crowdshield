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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crowdshield/internal/config"
)

const productionPasswordCanary = "production-password-canary-do-not-emit"

type blockingListener struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (l *blockingListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.started) })
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *blockingListener) Addr() net.Addr { return fakeAddr("production") }

func TestBuildProductionRuntimeAuthenticatesAndStopsWithoutLeaks(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	var logins atomic.Int32
	lapiServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/watchers/login" || request.Method != http.MethodPost {
			t.Error("production startup called an unexpected LAPI route")
			http.NotFound(writer, request)
			return
		}
		logins.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"code": 200, "expire": now.Add(time.Hour).Format(time.RFC3339), "token": "production-jwt-canary",
		})
	}))
	defer lapiServer.Close()

	temporary := t.TempDir()
	credentialPath := filepath.Join(temporary, "lapi.yaml")
	credentialBody := "url: " + lapiServer.URL + "\nlogin: crowdshield-test\npassword: " + productionPasswordCanary + "\n"
	if err := os.WriteFile(credentialPath, []byte(credentialBody), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	cfg := config.Defaults("test")
	cfg.Database.Path = filepath.Join(temporary, "crowdshield.db")
	cfg.CrowdSec.CredentialsFile = credentialPath
	cfg.CrowdSec.AllowedHTTPHosts = []string{"127.0.0.1"}
	cfg.Schedule.RunImmediately = false
	cfg.Schedule.StartupJitter = 0
	cfg.Schedule.Interval = config.Duration(time.Hour)
	cfg.Server.ListenAddress = "127.0.0.1:19090"
	listener := &blockingListener{started: make(chan struct{}), closed: make(chan struct{})}
	var logs bytes.Buffer
	runtime, err := BuildProduction(context.Background(), ProductionOptions{
		Config: cfg, Output: &logs, Now: func() time.Time { return now },
		Listen: func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != cfg.Server.ListenAddress {
				t.Error("production listener parameters changed")
			}
			return listener, nil
		},
	})
	if err != nil {
		t.Fatal("build production runtime")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-listener.started:
	case <-time.After(2 * time.Second):
		t.Fatal("production HTTP runtime did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("normal production cancellation failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("production runtime did not stop")
	}
	if logins.Load() != 1 {
		t.Fatal("production runtime did not authenticate exactly once")
	}
	text := logs.String()
	if strings.Contains(text, productionPasswordCanary) || strings.Contains(text, "production-jwt-canary") || strings.Contains(text, lapiServer.URL) {
		t.Fatal("production logs exposed credentials, token, or endpoint")
	}
	select {
	case <-listener.closed:
	default:
		t.Fatal("production listener remained open")
	}
}
