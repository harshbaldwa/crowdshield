package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"crowdshield/internal/cli"
)

func TestRunVersionDoesNotRequireConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatal("version command failed")
	}
	if !strings.HasPrefix(stdout.String(), "crowdshield dev ") {
		t.Fatal("version output missing safe build identity")
	}
	if stderr.Len() != 0 {
		t.Fatal("version wrote unexpected diagnostic output")
	}
}

func TestRunHelpUsesCommandDispatcher(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatal("help command was not dispatched")
	}
	if !strings.Contains(stdout.String(), "validate-config") || !strings.Contains(stdout.String(), "db") || stderr.Len() != 0 {
		t.Fatal("help did not use the complete bounded command surface")
	}
}

func TestProductionOptionsValidateConfigWithoutStateOrNetwork(t *testing.T) {
	temporary := t.TempDir()
	credentialPath := filepath.Join(temporary, "lapi.yaml")
	if err := os.WriteFile(credentialPath, []byte("url: https://unreachable.invalid\nlogin: test\npassword: test-password\n"), 0o600); err != nil {
		t.Fatal("write credential fixture")
	}
	configPath := filepath.Join(temporary, "crowdshield.yaml")
	body := "crowdsec:\n  credentials_file: " + strconv.Quote(credentialPath) + "\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal("write config fixture")
	}
	var stdout, stderr bytes.Buffer
	code := cli.Execute(context.Background(), []string{"validate-config", "--config", configPath}, &stdout, &stderr, productionOptions())
	if code != cli.ExitSuccess || stdout.String() != "configuration valid\n" || stderr.Len() != 0 {
		t.Fatal("production validate-config wiring failed")
	}
}

func TestProductionOptionsWireAllActions(t *testing.T) {
	actions := productionOptions().Actions
	if actions.ValidateConfig == nil || actions.Run == nil || actions.Sync == nil || actions.Status == nil ||
		actions.ListFeeds == nil || actions.Explain == nil || actions.Prune == nil || actions.DBCheck == nil {
		t.Fatal("one or more production CLI actions are not wired")
	}
}

func TestSignalContextCancelsOnSIGTERM(t *testing.T) {
	ctx, stop := signalContext(context.Background())
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal("send SIGTERM to test process")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("SIGTERM did not cancel the application context")
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"not-a-command"}, &stdout, &stderr); code != 2 {
		t.Fatal("unexpected usage exit code")
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatal("unknown command did not return concise usage")
	}
}
