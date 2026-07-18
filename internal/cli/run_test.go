package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
)

func TestRunPassesConfigurationModeContextAndLogWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loadedPath := ""
	called := false
	options := Options{
		Version: buildinfo.Current(),
		LoadConfig: func(path string) (config.Config, error) {
			loadedPath = path
			return config.Defaults("test"), nil
		},
		Actions: Actions{Run: func(received context.Context, cfg config.Config, once bool, output io.Writer) error {
			called = true
			if received != ctx || !once || output == nil || cfg.Schedule.Interval.Duration() == 0 {
				t.Error("run backend did not receive validated execution inputs")
			}
			_, _ = io.WriteString(output, "bounded-service-log\n")
			return nil
		}},
	}
	var stdout, stderr bytes.Buffer
	code := Execute(ctx, []string{"run", "--config", "/safe/runtime.yaml", "--run-once"}, &stdout, &stderr, options)
	if code != ExitSuccess || !called || loadedPath != "/safe/runtime.yaml" || stdout.String() != "bounded-service-log\n" || stderr.Len() != 0 {
		t.Fatalf("unexpected run result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunDiscardsBackendErrorText(t *testing.T) {
	const canary = "runtime-error-canary-do-not-emit"
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{Run: func(context.Context, config.Config, bool, io.Writer) error {
			return errors.New(canary)
		}},
	}
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"run"}, &stdout, &stderr, options)
	if code != ExitOperational || stdout.Len() != 0 || stderr.String() != "runtime failed\n" || strings.Contains(stderr.String(), canary) {
		t.Fatal("runtime failure was not reduced to a fixed diagnostic")
	}
}
