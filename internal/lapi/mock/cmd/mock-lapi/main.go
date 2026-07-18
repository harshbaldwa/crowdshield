package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"crowdshield/internal/lapi/mock"
)

var errInvalidRuntime = errors.New("invalid mock runtime")

func run(ctx context.Context, listener net.Listener, stdout, _ io.Writer) error {
	if ctx == nil || listener == nil || stdout == nil {
		return errInvalidRuntime
	}
	server := &http.Server{
		Handler:           mock.NewHandler(mock.Config{MachineID: "crowdshield-test", Password: "mock-password"}),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	if _, err := fmt.Fprintln(stdout, "mock-lapi ready"); err != nil {
		_ = server.Close()
		<-serveDone
		return errInvalidRuntime
	}

	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errInvalidRuntime
		}
		return nil
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownContext)
		serveErr := <-serveDone
		if shutdownErr != nil || (serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed)) {
			return errInvalidRuntime
		}
		return nil
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// #nosec G102 -- This test-only peer must bind the container interface; the harness uses a unique internal-only network and publishes no port.
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mock-lapi failed")
		os.Exit(1)
	}
	if err := run(ctx, listener, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mock-lapi failed")
		os.Exit(1)
	}
}
