package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

type readyWriter struct {
	ready chan struct{}
}

func (writer readyWriter) Write(payload []byte) (int, error) {
	select {
	case writer.ready <- struct{}{}:
	default:
	}
	return len(payload), nil
}

func TestRunServesSyntheticLAPIAndShutsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("unable to create test listener")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, listener, readyWriter{ready: ready}, io.Discard) }()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("mock LAPI did not report ready")
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/v1/watchers/login", nil)
	if err != nil {
		t.Fatal("unable to create request")
	}
	request.Header.Set("User-Agent", "crowdshield/test")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal("mock LAPI was not reachable")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("mock LAPI did not enforce its synthetic credentials")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("mock LAPI did not shut down cleanly")
		}
	case <-time.After(time.Second):
		t.Fatal("mock LAPI shutdown timed out")
	}
}
