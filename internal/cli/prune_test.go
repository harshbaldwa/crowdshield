package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
)

func TestPruneDefaultsToPlanAndRequiresExactConfirmation(t *testing.T) {
	confirmedCalls := make([]bool, 0)
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{Prune: func(_ context.Context, _ config.Config, confirmed bool) (PruneResult, error) {
			confirmedCalls = append(confirmedCalls, confirmed)
			return PruneResult{SyncRuns: 2, FeedEntries: 3}, nil
		}},
	}
	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), []string{"prune"}, &stdout, &stderr, options); code != ExitSuccess || !strings.Contains(stdout.String(), "mode=plan sync_runs=2") {
		t.Fatal("prune did not default to a dry plan")
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute(context.Background(), []string{"prune", "--confirm", "wrong"}, &stdout, &stderr, options); code != ExitUsage || len(confirmedCalls) != 1 {
		t.Fatal("incorrect prune confirmation reached backend")
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute(context.Background(), []string{"prune", "--confirm", PruneConfirmation}, &stdout, &stderr, options); code != ExitSuccess || !strings.Contains(stdout.String(), "mode=applied") {
		t.Fatal("exact prune confirmation did not apply bounded cleanup")
	}
	if len(confirmedCalls) != 2 || confirmedCalls[0] || !confirmedCalls[1] {
		t.Fatalf("unexpected prune modes: %v", confirmedCalls)
	}
}

func TestPruneOwnershipConflictUsesExitFour(t *testing.T) {
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{Prune: func(context.Context, config.Config, bool) (PruneResult, error) {
			return PruneResult{OwnershipConflicts: 1}, nil
		}},
	}
	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), []string{"prune"}, &stdout, &stderr, options); code != ExitOwnership || !strings.Contains(stdout.String(), "ownership_conflicts=1") {
		t.Fatal("prune ownership conflict did not fail closed")
	}
}
