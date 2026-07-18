package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
)

func TestDBCheckUsesFixedReadOnlyResult(t *testing.T) {
	calls := 0
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions:    Actions{DBCheck: func(context.Context, config.Config) error { calls++; return nil }},
	}
	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), []string{"db", "check"}, &stdout, &stderr, options); code != ExitSuccess || stdout.String() != "database ok\n" || stderr.Len() != 0 || calls != 1 {
		t.Fatal("database check did not use bounded success output")
	}

	options.Actions.DBCheck = func(context.Context, config.Config) error { return errors.New("db-canary-do-not-emit") }
	stdout.Reset()
	stderr.Reset()
	if code := Execute(context.Background(), []string{"db", "check"}, &stdout, &stderr, options); code != ExitOperational || stderr.String() != "database check failed\n" || strings.Contains(stderr.String(), "canary") {
		t.Fatal("database check exposed backend error")
	}
}
