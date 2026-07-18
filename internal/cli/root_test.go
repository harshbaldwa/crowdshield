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

func TestHelpAndVersionDoNotLoadConfiguration(t *testing.T) {
	loads := 0
	options := Options{
		Version: buildinfo.Info{Name: "crowdshield", Version: "test", Revision: "unknown", BuildDate: "unknown", GoVersion: "go-test", GOOS: "linux", GOARCH: "amd64"},
		LoadConfig: func(string) (config.Config, error) {
			loads++
			return config.Config{}, errors.New("must not load")
		},
	}
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"help"}, want: "validate-config"},
		{args: []string{"version"}, want: "crowdshield test"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Execute(context.Background(), test.args, &stdout, &stderr, options); code != ExitSuccess {
			t.Fatalf("configuration-independent command failed: %v", test.args)
		}
		if !strings.Contains(stdout.String(), test.want) || stderr.Len() != 0 {
			t.Fatalf("unexpected command output: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
	if loads != 0 {
		t.Fatal("help or version loaded configuration")
	}
}

func TestValidateConfigLoadsOnlySelectedConfiguration(t *testing.T) {
	loadedPath := ""
	backendCalls := 0
	options := Options{
		Version: buildinfo.Current(),
		LoadConfig: func(path string) (config.Config, error) {
			loadedPath = path
			return config.Defaults("test"), nil
		},
		Actions: Actions{Run: func(context.Context, config.Config, bool, io.Writer) error {
			backendCalls++
			return nil
		}},
	}
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"validate-config", "--config", "/safe/config.yaml"}, &stdout, &stderr, options)
	if code != ExitSuccess || loadedPath != "/safe/config.yaml" || stdout.String() != "configuration valid\n" || stderr.Len() != 0 {
		t.Fatalf("unexpected validate-config result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if backendCalls != 0 {
		t.Fatal("validate-config performed a backend action")
	}
}

func TestValidateConfigChecksCredentialShapeAndRedactsFailure(t *testing.T) {
	const canary = "credential-validation-canary-do-not-emit"
	checked := false
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{ValidateConfig: func(context.Context, config.Config) error {
			checked = true
			return errors.New(canary)
		}},
	}
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"validate-config"}, &stdout, &stderr, options)
	if code != ExitUsage || !checked || stdout.Len() != 0 || stderr.String() != "configuration invalid\n" || strings.Contains(stderr.String(), canary) {
		t.Fatal("credential validation failure was not checked and reduced to a fixed diagnostic")
	}
}

func TestUnknownCommandReturnsStableUsageWithoutEchoingArgument(t *testing.T) {
	const canary = "unknown-command-canary-do-not-emit"
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{canary}, &stdout, &stderr, Options{Version: buildinfo.Current()})
	if code != ExitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") || strings.Contains(stderr.String(), canary) {
		t.Fatal("unknown command output was not fixed and private")
	}
}
