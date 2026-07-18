package app

import (
	"context"
	"errors"
	"os"
	"time"

	"crowdshield/internal/cli"
	"crowdshield/internal/config"
	"crowdshield/internal/state"
)

var ErrOperatorPrune = errors.New("operator prune failed")
var ErrOperatorDBCheck = errors.New("operator database check failed")

type operatorPruneOptions struct {
	Now func() time.Time
}

func mapPruneResult(result state.PruneResult, conflicts int64) cli.PruneResult {
	return cli.PruneResult{
		SyncRuns:           result.SyncRuns,
		Operations:         result.Operations,
		Decisions:          result.Decisions,
		Alerts:             result.Alerts,
		EnforcementObjects: result.EnforcementObjects,
		FeedEntries:        result.FeedEntries,
		OwnershipConflicts: conflicts,
	}
}

func pruneCLIWithOptions(ctx context.Context, cfg config.Config, confirmed bool, options operatorPruneOptions) (cli.PruneResult, error) {
	if ctx == nil || options.Now == nil || cfg.Validate() != nil {
		return cli.PruneResult{}, ErrOperatorPrune
	}
	now := options.Now().UTC()
	if now.IsZero() || now.Unix() < 0 {
		return cli.PruneResult{}, ErrOperatorPrune
	}
	stateOptions := state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		IntegrityCheck: cfg.Database.IntegrityCheckOnStart,
	}
	if confirmed {
		info, err := os.Lstat(cfg.Database.Path)
		if err != nil || !info.Mode().IsRegular() {
			return cli.PruneResult{}, ErrOperatorPrune
		}
		store, err := state.Open(ctx, stateOptions)
		if err != nil {
			return cli.PruneResult{}, ErrOperatorPrune
		}
		conflicts, conflictErr := store.CountAmbiguousOperations(ctx)
		if conflictErr != nil {
			_ = store.Close()
			return cli.PruneResult{}, ErrOperatorPrune
		}
		if conflicts > 0 {
			planned, planErr := store.PlanPruneHistory(
				ctx, now, cfg.Database.HistoryRetention.Duration(), cfg.Database.MaxHistoryEntries,
			)
			closeErr := store.Close()
			result := mapPruneResult(planned, conflicts)
			if planErr != nil || closeErr != nil || result.Validate() != nil {
				return cli.PruneResult{}, ErrOperatorPrune
			}
			return result, nil
		}
		pruned, pruneErr := store.PruneHistory(
			ctx, now, cfg.Database.HistoryRetention.Duration(), cfg.Database.MaxHistoryEntries,
		)
		closeErr := store.Close()
		result := mapPruneResult(pruned, 0)
		if pruneErr != nil || closeErr != nil || result.Validate() != nil {
			return cli.PruneResult{}, ErrOperatorPrune
		}
		return result, nil
	}

	store, err := state.OpenReadOnly(ctx, stateOptions)
	if err != nil {
		return cli.PruneResult{}, ErrOperatorPrune
	}
	conflicts, conflictErr := store.CountAmbiguousOperations(ctx)
	planned, planErr := store.PlanPruneHistory(
		ctx, now, cfg.Database.HistoryRetention.Duration(), cfg.Database.MaxHistoryEntries,
	)
	closeErr := store.Close()
	result := mapPruneResult(planned, conflicts)
	if conflictErr != nil || planErr != nil || closeErr != nil || result.Validate() != nil {
		return cli.PruneResult{}, ErrOperatorPrune
	}
	return result, nil
}

// PruneCLI plans history pruning unless the caller supplied the exact
// destructive confirmation token parsed by the CLI.
func PruneCLI(ctx context.Context, cfg config.Config, confirmed bool) (cli.PruneResult, error) {
	return pruneCLIWithOptions(ctx, cfg, confirmed, operatorPruneOptions{Now: time.Now})
}

// DBCheckCLI verifies schema migration checksums and SQLite integrity without
// creating, migrating, or otherwise writing the configured database.
func DBCheckCLI(ctx context.Context, cfg config.Config) error {
	if ctx == nil || cfg.Validate() != nil {
		return ErrOperatorDBCheck
	}
	store, err := state.OpenReadOnly(ctx, state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(), IntegrityCheck: true,
	})
	if err != nil {
		return ErrOperatorDBCheck
	}
	version, versionErr := store.SchemaVersion(ctx)
	closeErr := store.Close()
	if versionErr != nil || version < 1 || closeErr != nil {
		return ErrOperatorDBCheck
	}
	return nil
}
