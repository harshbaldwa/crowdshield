package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
)

func TestExplainPrintsExplicitInputAndBoundedDecisionContext(t *testing.T) {
	result := ExplainResult{
		Canonical: "198.51.100.0/24", Kind: ExplainRange, Desired: true,
		Covered: true, CoveringPrefix: "198.51.100.0/23",
		Contributors: []string{"feed-two", "feed-one"}, Owned: true,
	}
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{Explain: func(_ context.Context, _ config.Config, input string) (ExplainResult, error) {
			if input != "198.51.100.0/24" {
				t.Error("explicit explain input changed")
			}
			return result, nil
		}},
	}
	for _, args := range [][]string{{"explain", "198.51.100.0/24"}, {"explain", "--json", "198.51.100.0/24"}} {
		var stdout, stderr bytes.Buffer
		if code := Execute(context.Background(), args, &stdout, &stderr, options); code != ExitSuccess || stderr.Len() != 0 {
			t.Fatalf("explain failed: %v", args)
		}
		text := stdout.String()
		if !strings.Contains(text, "198.51.100.0/24") || !strings.Contains(text, "198.51.100.0/23") ||
			strings.Index(text, "feed-one") > strings.Index(text, "feed-two") {
			t.Fatalf("explain output was incomplete or nondeterministic: %q", text)
		}
	}
}

func TestExplainRejectsInvalidInputAndMapsOwnershipConflict(t *testing.T) {
	called := false
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{Explain: func(context.Context, config.Config, string) (ExplainResult, error) {
			called = true
			return ExplainResult{Canonical: "198.51.100.9", Kind: ExplainIP, OwnershipConflict: true}, nil
		}},
	}
	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), []string{"explain", "not-an-address"}, &stdout, &stderr, options); code != ExitUsage || called {
		t.Fatal("invalid explain input reached backend")
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute(context.Background(), []string{"explain", "198.51.100.9"}, &stdout, &stderr, options); code != ExitOwnership || !strings.Contains(stdout.String(), "ownership_conflict=true") {
		t.Fatal("ownership conflict did not use stable exit 4")
	}
}
