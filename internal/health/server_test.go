package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"crowdshield/internal/ops"
)

type eventCollector struct {
	mu     sync.Mutex
	events []ops.Event
}

func (c *eventCollector) Observe(_ context.Context, event ops.Event) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
}

func (c *eventCollector) Codes() []ops.Code {
	c.mu.Lock()
	defer c.mu.Unlock()
	codes := make([]ops.Code, 0, len(c.events))
	for _, event := range c.events {
		codes = append(codes, event.Code)
	}
	return codes
}

func serverOptions(handler http.Handler, clock Clock, observer Observer) ServerOptions {
	return ServerOptions{
		Handler: handler, Clock: clock, Observer: observer,
		ReadHeaderTimeout: time.Second, ReadTimeout: time.Second,
		WriteTimeout: time.Second, IdleTimeout: time.Second,
		ShutdownTimeout: time.Second,
	}
}

func waitServer(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not stop")
		return nil
	}
}

func TestServerServesAndShutsDownIdempotentlyWithLifecycleEvents(t *testing.T) {
	clock := newFakeClock()
	tracker := readyTracker(t, clock)
	handler, err := NewHandler(tracker, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal("valid handler rejected")
	}
	collector := &eventCollector{}
	server, err := NewServer(serverOptions(handler, clock, collector))
	if err != nil {
		t.Fatal("valid HTTP server options rejected")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback listener failed")
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal("HTTP health request failed")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("running HTTP server did not serve health")
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal("graceful HTTP shutdown failed")
	}
	if err := waitServer(t, done); err != nil {
		t.Fatal("HTTP Serve returned an operational error after shutdown")
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal("repeated HTTP shutdown was not idempotent")
	}
	codes := collector.Codes()
	if len(codes) != 2 || codes[0] != ops.CodeHTTPStarted || codes[1] != ops.CodeHTTPStopped {
		t.Fatal("HTTP lifecycle events were not emitted exactly once in order")
	}
}

func TestServerShutdownIsBoundedAndForceClosesConnections(t *testing.T) {
	clock := newFakeClock()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		writer.WriteHeader(http.StatusOK)
	})
	options := serverOptions(handler, clock, &eventCollector{})
	options.ShutdownTimeout = 25 * time.Millisecond
	server, err := NewServer(options)
	if err != nil {
		t.Fatal("valid bounded HTTP server options rejected")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback listener failed")
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: time.Second}
		response, requestErr := client.Get("http://" + listener.Addr().String() + "/blocked")
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- requestErr
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("blocking HTTP handler did not start")
	}
	started := time.Now()
	err = server.Shutdown(context.Background())
	elapsed := time.Since(started)
	if !errors.Is(err, ErrShutdownTimeout) {
		t.Fatal("bounded HTTP shutdown did not return its fixed timeout category")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatal("HTTP shutdown exceeded its configured bound")
	}
	close(release)
	if err := waitServer(t, serveDone); err != nil {
		t.Fatal("forced HTTP close leaked a Serve error")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("forced HTTP close left a client request running")
	}
}
