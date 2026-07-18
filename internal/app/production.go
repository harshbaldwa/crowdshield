package app

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
	"crowdshield/internal/credentials"
	"crowdshield/internal/feed"
	"crowdshield/internal/health"
	"crowdshield/internal/lapi"
	"crowdshield/internal/logsafe"
	"crowdshield/internal/metrics"
	"crowdshield/internal/notify"
	"crowdshield/internal/ops"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/scheduler"
	"crowdshield/internal/state"
	"crowdshield/internal/syncer"
)

var ErrProductionBuild = errors.New("production runtime build failure")

type ListenFunc func(network, address string) (net.Listener, error)

type ProductionOptions struct {
	Config config.Config
	Output io.Writer
	Now    func() time.Time
	Listen ListenFunc
}

func enabledFeedNames(cfg config.Config) []string {
	names := make([]string, 0, len(cfg.Feeds))
	for _, configured := range cfg.Feeds {
		if configured.Enabled {
			names = append(names, configured.Name)
		}
	}
	return names
}

func BuildProduction(ctx context.Context, options ProductionOptions) (_ *Runtime, returnErr error) {
	if ctx == nil || options.Output == nil {
		return nil, ErrProductionBuild
	}
	cfg := options.Config
	if err := cfg.Validate(); err != nil {
		return nil, ErrProductionBuild
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Listen == nil {
		options.Listen = net.Listen
	}
	logger, err := logsafe.New(options.Output, cfg.Logging.Level)
	if err != nil {
		return nil, ErrProductionBuild
	}

	credentialSet, err := (credentials.Loader{
		MaxBytes: credentials.DefaultMaxBytes, StrictPermissions: true,
		AllowedHTTPHosts: append([]string(nil), cfg.CrowdSec.AllowedHTTPHosts...),
	}).Load(cfg.CrowdSec.CredentialsFile)
	if err != nil {
		return nil, ErrProductionBuild
	}
	var store *state.Store
	var lapiClient *lapi.Client
	var fetcher *feed.Fetcher
	var notificationTransport *notify.HTTPTransport
	var notificationManager *notify.Manager
	var listener net.Listener
	owned := true
	defer func() {
		if !owned {
			return
		}
		if notificationManager != nil {
			notificationManager.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		if notificationTransport != nil {
			notificationTransport.CloseIdleConnections()
		}
		if fetcher != nil {
			fetcher.CloseIdleConnections()
		}
		if lapiClient != nil {
			lapiClient.CloseIdleConnections()
		}
		if store != nil {
			_ = store.Close()
		}
		credentialSet.Destroy()
	}()

	store, err = state.Open(ctx, state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		IntegrityCheck: cfg.Database.IntegrityCheckOnStart,
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	lapiClient, err = lapi.New(lapi.Options{
		Credentials: credentialSet, UserAgent: cfg.Validation.UserAgent,
		RequestTimeout:    cfg.CrowdSec.RequestTimeout.Duration(),
		ConnectTimeout:    cfg.CrowdSec.ConnectTimeout.Duration(),
		MaxResponseBytes:  cfg.CrowdSec.MaxResponseBytes,
		AuthRefreshBefore: cfg.CrowdSec.AuthRefreshBefore.Duration(), Now: options.Now,
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	reconciler, err := reconcile.New(reconcile.Options{
		Store: store, LAPI: lapiClient, MachineID: credentialSet.Login(),
		Duration: cfg.Decisions.Duration.Duration(), RefreshBefore: cfg.Decisions.RefreshBefore.Duration(),
		BatchSize: cfg.CrowdSec.BatchSize, Now: options.Now,
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	fetcher, err = feed.NewFetcher(feed.FetcherOptions{
		UserAgent: cfg.Validation.UserAgent, MaxRedirects: cfg.Validation.MaxRedirects,
		AllowHTTP: cfg.Validation.AllowHTTP, ConnectTimeout: cfg.CrowdSec.ConnectTimeout.Duration(),
		DNSLookupTimeout:      cfg.Validation.DNSLookupTimeout.Duration(),
		TLSHandshakeTimeout:   cfg.CrowdSec.ConnectTimeout.Duration(),
		ResponseHeaderTimeout: cfg.CrowdSec.RequestTimeout.Duration(),
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	engine, err := syncer.New(syncer.Options{
		Config: cfg, Store: store, Fetcher: fetcher, Reconciler: reconciler, Now: options.Now,
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	metricRegistry, err := metrics.New(metrics.Options{Build: buildinfo.Current(), Feeds: enabledFeedNames(cfg)})
	if err != nil {
		return nil, ErrProductionBuild
	}
	readiness, err := health.New(health.Options{
		MaxSyncAge:      cfg.Server.ReadinessMaxSyncAge.Duration(),
		LAPIOutageGrace: cfg.Server.LAPIUnreachableGrace.Duration(),
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	observer, err := NewEventFanout(logger, metricRegistry, readiness)
	if err != nil {
		return nil, ErrProductionBuild
	}

	var transport notify.Transport
	if cfg.Notifications.Enabled {
		notificationTransport, err = notify.NewHTTPTransport(notify.HTTPOptions{
			ServerURL: cfg.Notifications.ServerURL, Topic: cfg.Notifications.Topic,
			Token: cfg.Notifications.Token, Timeout: cfg.Notifications.RequestTimeout.Duration(),
			AllowHTTP: cfg.Notifications.AllowHTTP,
		})
		if err != nil {
			return nil, ErrProductionBuild
		}
		transport = notificationTransport
	}
	notificationManager, err = notify.NewManager(notify.ManagerOptions{
		Enabled: cfg.Notifications.Enabled, Store: store.NotificationStates(), Transport: transport,
		Observer: observer, MinimumSeverity: ops.Severity(cfg.Notifications.MinimumSeverity),
		FailureThreshold: cfg.Notifications.FailureThreshold, Cooldown: cfg.Notifications.Cooldown.Duration(),
		RecoveryNotifications:         cfg.Notifications.RecoveryNotifications,
		SuspiciousChangeNotifications: cfg.Notifications.SuspiciousChangeNotifications,
		StaleSyncNotifications:        cfg.Notifications.StaleSyncNotifications,
		StartupNotification:           cfg.Notifications.StartupNotification,
		FirstSuccessNotification:      cfg.Notifications.FirstSuccessNotification,
		RoutineSuccessNotification:    cfg.Notifications.SuccessNotification,
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	job, err := NewSyncJob(SyncJobOptions{
		Engine: engine, State: store, Metrics: metricRegistry, Health: readiness,
		Notifications: notificationManager, Observer: observer, Now: options.Now,
		FinalizationTimeout: cfg.Database.BusyTimeout.Duration(),
		StaleAfter:          cfg.Notifications.StaleSyncAfter.Duration(),
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	runScheduler, err := scheduler.New(scheduler.Options{
		Interval: cfg.Schedule.Interval.Duration(), StartupJitter: cfg.Schedule.StartupJitter.Duration(),
		RunImmediately: cfg.Schedule.RunImmediately,
		Retry: scheduler.RetryPolicy{
			MaxAttempts:    cfg.Schedule.Retry.MaxAttempts,
			InitialBackoff: cfg.Schedule.Retry.InitialBackoff.Duration(),
			MaxBackoff:     cfg.Schedule.Retry.MaxBackoff.Duration(),
		},
		Job: job.Run, Observer: observer,
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	handler, err := health.NewHandler(readiness, metricRegistry)
	if err != nil {
		return nil, ErrProductionBuild
	}
	httpRuntime, err := health.NewServer(health.ServerOptions{
		Handler: handler, Observer: observer,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration(),
		ReadTimeout:       cfg.Server.ReadTimeout.Duration(), WriteTimeout: cfg.Server.WriteTimeout.Duration(),
		IdleTimeout: cfg.Server.IdleTimeout.Duration(), ShutdownTimeout: cfg.Server.ShutdownTimeout.Duration(),
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	listener, err = options.Listen("tcp", cfg.Server.ListenAddress)
	if err != nil {
		return nil, ErrProductionBuild
	}
	idleClosers := []IdleCloser{fetcher, lapiClient}
	if notificationTransport != nil {
		idleClosers = append(idleClosers, notificationTransport)
	}
	runtime, err := NewRuntime(RuntimeOptions{
		State: store, Authenticator: lapiClient, Health: readiness, Metrics: metricRegistry,
		Notifications: notificationManager, Scheduler: runScheduler, HTTP: httpRuntime,
		Listener: listener, Observer: observer, IdleClosers: idleClosers,
		Credentials: credentialSet, Now: options.Now,
		HistoryRetention: cfg.Database.HistoryRetention.Duration(), PruneInterval: 24 * time.Hour,
	})
	if err != nil {
		return nil, ErrProductionBuild
	}
	owned = false
	return runtime, nil
}
