package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"crowdshield/internal/cli"
	"crowdshield/internal/config"
	"crowdshield/internal/credentials"
	"crowdshield/internal/feed"
	"crowdshield/internal/lapi"
	"crowdshield/internal/ops"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/state"
	"crowdshield/internal/syncer"
)

var ErrOperatorConfig = errors.New("operator configuration invalid")
var ErrOperatorRuntime = errors.New("operator runtime failed")
var ErrOperatorSync = errors.New("operator synchronization failed")

type operatorFetchClient interface {
	Fetch(context.Context, feed.FetchRequest) (feed.FetchResult, error)
}

type operatorSyncOptions struct {
	Now     func() time.Time
	Fetcher operatorFetchClient
}

type operatorRunOptions struct {
	Sync func(context.Context, config.Config, cli.SyncRequest) (ops.Result, error)
}

// ValidateCLIConfig validates configuration and the dedicated CrowdSec
// credential-file shape without opening state or contacting any remote service.
func ValidateCLIConfig(ctx context.Context, cfg config.Config) error {
	if ctx == nil || ctx.Err() != nil || cfg.Validate() != nil {
		return ErrOperatorConfig
	}
	loaded, err := (credentials.Loader{
		MaxBytes:          credentials.DefaultMaxBytes,
		StrictPermissions: true,
		AllowedHTTPHosts:  cfg.CrowdSec.AllowedHTTPHosts,
	}).Load(cfg.CrowdSec.CredentialsFile)
	if err != nil {
		return ErrOperatorConfig
	}
	loaded.Destroy()
	if ctx.Err() != nil {
		return ErrOperatorConfig
	}
	return nil
}

// RunCLI constructs and runs the complete production application. It returns
// only a fixed error category; detailed causes remain in bounded runtime events.
func RunCLI(ctx context.Context, cfg config.Config, runOnce bool, output io.Writer) error {
	return runCLIWithOptions(ctx, cfg, runOnce, output, operatorRunOptions{Sync: SyncCLI})
}

func runCLIWithOptions(ctx context.Context, cfg config.Config, runOnce bool, output io.Writer, options operatorRunOptions) error {
	if ctx == nil || output == nil || cfg.Validate() != nil {
		return ErrOperatorRuntime
	}
	if runOnce {
		if options.Sync == nil {
			return ErrOperatorRuntime
		}
		result, err := options.Sync(ctx, cfg, cli.SyncRequest{})
		if err != nil || result.Validate() != nil || result.Outcome != ops.OutcomeSuccess {
			return ErrOperatorRuntime
		}
		_, _ = fmt.Fprintln(output, "synchronization complete")
		return nil
	}
	runtime, err := BuildProduction(ctx, ProductionOptions{Config: cfg, Output: output})
	if err != nil {
		return ErrOperatorRuntime
	}
	if err := runtime.Run(ctx); err != nil {
		return ErrOperatorRuntime
	}
	return nil
}

func operatorFailure(now time.Time, failure ops.FailureCategory, retryable bool) ops.Result {
	now = now.UTC()
	return ops.Result{
		Outcome: ops.OutcomeFailed, Failure: failure, Retryable: retryable,
		StartedAt: now, CompletedAt: now,
	}
}

func newOperatorFetcher(cfg config.Config) (*feed.Fetcher, error) {
	return feed.NewFetcher(feed.FetcherOptions{
		UserAgent: cfg.Validation.UserAgent, MaxRedirects: cfg.Validation.MaxRedirects,
		AllowHTTP: cfg.Validation.AllowHTTP, ConnectTimeout: cfg.CrowdSec.ConnectTimeout.Duration(),
		DNSLookupTimeout:      cfg.Validation.DNSLookupTimeout.Duration(),
		TLSHandshakeTimeout:   cfg.CrowdSec.ConnectTimeout.Duration(),
		ResponseHeaderTimeout: cfg.CrowdSec.RequestTimeout.Duration(),
	})
}

func syncCLIWithOptions(ctx context.Context, cfg config.Config, request cli.SyncRequest, options operatorSyncOptions) (ops.Result, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	startedAt := options.Now().UTC()
	if startedAt.IsZero() {
		return ops.Result{}, ErrOperatorSync
	}
	if ctx == nil || cfg.Validate() != nil || (request.Feed != "" && !ops.ValidFeedName(request.Feed)) {
		return operatorFailure(startedAt, ops.FailureConfig, false), nil
	}
	if !request.DryRun {
		return syncCLIEnforceWithOptions(ctx, cfg, request, options, startedAt)
	}

	credentialSet, err := (credentials.Loader{
		MaxBytes: credentials.DefaultMaxBytes, StrictPermissions: true,
		AllowedHTTPHosts: append([]string(nil), cfg.CrowdSec.AllowedHTTPHosts...),
	}).Load(cfg.CrowdSec.CredentialsFile)
	if err != nil {
		return operatorFailure(startedAt, ops.FailureConfig, false), nil
	}
	defer credentialSet.Destroy()

	readStore, err := state.OpenReadOnly(ctx, state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		IntegrityCheck: cfg.Database.IntegrityCheckOnStart,
	})
	var store operatorDryStore
	if err != nil {
		if _, statErr := os.Stat(cfg.Database.Path); !os.IsNotExist(statErr) {
			return operatorFailure(startedAt, ops.FailureDatabase, true), nil
		}
		store = &emptyOperatorStore{}
	} else {
		store = readStore
		defer func() { _ = readStore.Close() }()
	}

	lapiClient, err := lapi.New(lapi.Options{
		Credentials: credentialSet, UserAgent: cfg.Validation.UserAgent,
		RequestTimeout: cfg.CrowdSec.RequestTimeout.Duration(), ConnectTimeout: cfg.CrowdSec.ConnectTimeout.Duration(),
		MaxResponseBytes: cfg.CrowdSec.MaxResponseBytes, AuthRefreshBefore: cfg.CrowdSec.AuthRefreshBefore.Duration(),
		Now: options.Now,
	})
	if err != nil {
		return operatorFailure(startedAt, ops.FailureConfig, false), nil
	}
	defer lapiClient.CloseIdleConnections()

	reconciler, err := reconcile.New(reconcile.Options{
		Store: store, LAPI: lapiClient, MachineID: credentialSet.Login(),
		Duration: cfg.Decisions.Duration.Duration(), RefreshBefore: cfg.Decisions.RefreshBefore.Duration(),
		BatchSize: cfg.CrowdSec.BatchSize, Now: options.Now,
	})
	if err != nil {
		return operatorFailure(startedAt, ops.FailureInternal, false), nil
	}
	fetcher := options.Fetcher
	if fetcher == nil {
		productionFetcher, fetchErr := newOperatorFetcher(cfg)
		if fetchErr != nil {
			return operatorFailure(startedAt, ops.FailureConfig, false), nil
		}
		defer productionFetcher.CloseIdleConnections()
		fetcher = productionFetcher
	}
	engine, err := syncer.New(syncer.Options{
		Config: cfg, Store: store, Fetcher: fetcher, Reconciler: reconciler, Now: options.Now,
	})
	if err != nil {
		return operatorFailure(startedAt, ops.FailureConfig, false), nil
	}
	report, runErr := engine.Run(ctx, syncer.RunOptions{FeedName: request.Feed, DryRun: true})
	active, activeErr := store.ListActiveDecisions(context.WithoutCancel(ctx))
	if activeErr != nil {
		runErr = &syncer.Error{Category: syncer.ErrState}
	}
	completedAt := normalizedCompletion(startedAt, options.Now())
	result, err := ResultFromSync(report, runErr, startedAt, completedAt, len(active))
	if err != nil {
		return operatorFailure(completedAt, ops.FailureInternal, false), ErrOperatorSync
	}
	return result, nil
}

func syncCLIEnforceWithOptions(ctx context.Context, cfg config.Config, request cli.SyncRequest, options operatorSyncOptions, startedAt time.Time) (ops.Result, error) {
	credentialSet, err := (credentials.Loader{
		MaxBytes: credentials.DefaultMaxBytes, StrictPermissions: true,
		AllowedHTTPHosts: append([]string(nil), cfg.CrowdSec.AllowedHTTPHosts...),
	}).Load(cfg.CrowdSec.CredentialsFile)
	if err != nil {
		return operatorFailure(startedAt, ops.FailureConfig, false), nil
	}
	defer credentialSet.Destroy()

	store, err := state.Open(ctx, state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		IntegrityCheck: cfg.Database.IntegrityCheckOnStart,
	})
	if err != nil {
		return operatorFailure(startedAt, ops.FailureDatabase, true), nil
	}
	defer func() { _ = store.Close() }()
	if _, err := store.RecoverInterruptedSyncRuns(ctx, startedAt); err != nil {
		return operatorFailure(startedAt, ops.FailureDatabase, true), nil
	}

	lapiClient, err := lapi.New(lapi.Options{
		Credentials: credentialSet, UserAgent: cfg.Validation.UserAgent,
		RequestTimeout: cfg.CrowdSec.RequestTimeout.Duration(), ConnectTimeout: cfg.CrowdSec.ConnectTimeout.Duration(),
		MaxResponseBytes: cfg.CrowdSec.MaxResponseBytes, AuthRefreshBefore: cfg.CrowdSec.AuthRefreshBefore.Duration(),
		Now: options.Now,
	})
	if err != nil {
		return operatorFailure(startedAt, ops.FailureConfig, false), nil
	}
	defer lapiClient.CloseIdleConnections()
	reconciler, err := reconcile.New(reconcile.Options{
		Store: store, LAPI: lapiClient, MachineID: credentialSet.Login(),
		Duration: cfg.Decisions.Duration.Duration(), RefreshBefore: cfg.Decisions.RefreshBefore.Duration(),
		BatchSize: cfg.CrowdSec.BatchSize, Now: options.Now,
	})
	if err != nil {
		return operatorFailure(startedAt, ops.FailureInternal, false), nil
	}
	fetcher := options.Fetcher
	if fetcher == nil {
		productionFetcher, fetchErr := newOperatorFetcher(cfg)
		if fetchErr != nil {
			return operatorFailure(startedAt, ops.FailureConfig, false), nil
		}
		defer productionFetcher.CloseIdleConnections()
		fetcher = productionFetcher
	}
	engine, err := syncer.New(syncer.Options{
		Config: cfg, Store: store, Fetcher: fetcher, Reconciler: reconciler, Now: options.Now,
	})
	if err != nil {
		return operatorFailure(startedAt, ops.FailureConfig, false), nil
	}

	runID, err := store.BeginSyncRun(ctx, state.SyncModeEnforce, request.Feed, startedAt)
	if err != nil {
		return operatorFailure(startedAt, ops.FailureDatabase, true), nil
	}
	var report syncer.Report
	runErr := lapiClient.Authenticate(ctx)
	if runErr == nil {
		report, runErr = engine.Run(ctx, syncer.RunOptions{FeedName: request.Feed})
	}
	activeDecisions := 0
	if !errors.Is(runErr, context.Canceled) {
		active, activeErr := store.ListActiveDecisions(ctx)
		if activeErr != nil {
			runErr = &syncer.Error{Category: syncer.ErrState}
		} else {
			activeDecisions = len(active)
		}
	}
	completedAt := normalizedCompletion(startedAt, options.Now())
	result, conversionErr := ResultFromSync(report, runErr, startedAt, completedAt, activeDecisions)
	if conversionErr != nil {
		result = fixedFailureResult(ops.FailureInternal, false, startedAt, completedAt, ops.Result{})
	}
	finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.Database.BusyTimeout.Duration())
	completeErr := store.CompleteSyncRun(finalizeContext, runID, result)
	cancel()
	if completeErr != nil {
		result = fixedFailureResult(ops.FailureDatabase, true, startedAt, completedAt, result)
	}
	return result, nil
}

// SyncCLI runs exactly one synchronization and returns only bounded aggregate
// operational state. Dry-run never authenticates or writes local state.
func SyncCLI(ctx context.Context, cfg config.Config, request cli.SyncRequest) (ops.Result, error) {
	return syncCLIWithOptions(ctx, cfg, request, operatorSyncOptions{})
}
