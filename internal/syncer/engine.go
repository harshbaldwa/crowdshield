package syncer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"crowdshield/internal/config"
	"crowdshield/internal/feed"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/state"
)

var errUnsolicitedNotModified = errors.New("unsolicited not modified")

type stateStore interface {
	EnsureFeeds(context.Context, []state.FeedDefinition, time.Time) ([]state.FeedRecord, error)
	FeedByName(context.Context, string) (state.FeedRecord, error)
	ApplyFeedSnapshot(context.Context, string, state.FeedSnapshot, int, time.Time) (state.SnapshotResult, error)
	RecordFeedNotModified(context.Context, string, string, string, time.Time) error
	RecordFeedFailure(context.Context, string, string, time.Time, time.Time) error
	ListFeeds(context.Context) ([]state.FeedRecord, error)
	ListActiveEntries(context.Context) ([]state.StoredEntry, error)
}

type fetchClient interface {
	Fetch(context.Context, feed.FetchRequest) (feed.FetchResult, error)
}

type reconcileClient interface {
	Run(context.Context, reconcile.RunOptions) (reconcile.Report, error)
}

type Options struct {
	Config     config.Config
	Store      stateStore
	Fetcher    fetchClient
	Reconciler reconcileClient
	Now        func() time.Time
}

type RunOptions struct {
	FeedName string
	DryRun   bool
}

type FeedStatus string

const (
	FeedSucceeded FeedStatus = "succeeded"
	FeedFailed    FeedStatus = "failed"
	FeedUnchanged FeedStatus = "not_modified"
	FeedNotDue    FeedStatus = "not_due"
)

type FeedResult struct {
	Name       string
	Status     FeedStatus
	Accepted   int
	Rejected   int
	ErrorClass string
}

type Report struct {
	FeedsSucceeded    int
	FeedsFailed       int
	FeedsUnchanged    int
	FeedsNotDue       int
	SuspiciousChanges int
	Feeds             []FeedResult
	Reconcile         reconcile.Report
}

type Engine struct {
	config     config.Config
	store      stateStore
	fetcher    fetchClient
	reconciler reconcileClient
	now        func() time.Time
}

func New(options Options) (*Engine, error) {
	if options.Store == nil || options.Fetcher == nil || options.Reconciler == nil {
		return nil, syncError(ErrConfig, nil)
	}
	cfg := options.Config
	if err := cfg.Validate(); err != nil {
		return nil, syncError(ErrConfig, err)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Engine{config: cfg, store: options.Store, fetcher: options.Fetcher, reconciler: options.Reconciler, now: options.Now}, nil
}

func hashText(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func definitionHash(feedConfig config.FeedConfig) (string, error) {
	body, err := json.Marshal(feedConfig)
	if err != nil {
		return "", err
	}
	defer func() {
		for index := range body {
			body[index] = 0
		}
	}()
	return hashText(string(body)), nil
}

func feedDefinitions(configured []config.FeedConfig) ([]state.FeedDefinition, error) {
	definitions := make([]state.FeedDefinition, 0, len(configured))
	for _, item := range configured {
		hash, err := definitionHash(item)
		if err != nil {
			return nil, err
		}
		definitions = append(definitions, state.FeedDefinition{
			Name: item.Name, URLHash: hashText(item.URL), DefinitionHash: hash, Enabled: item.Enabled,
		})
	}
	return definitions, nil
}

func configuredAllowlists(items []config.CIDR) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		result = append(result, item.Prefix())
	}
	return result
}

func metadataAge(format feed.Format) time.Duration {
	if format == feed.FormatSpamhausDROPJSONL {
		return 72 * time.Hour
	}
	return 0
}

func feedFailureCategory(err error) string {
	var classified *feed.Error
	if errors.As(err, &classified) {
		return string(classified.Category)
	}
	return string(feed.ErrRequest)
}

func retryDelay(retry config.RetryConfig, consecutiveFailures int, requested time.Duration) time.Duration {
	delay := retry.InitialBackoff.Duration()
	maximum := retry.MaxBackoff.Duration()
	for attempt := 0; attempt < consecutiveFailures && delay < maximum; attempt++ {
		if delay > maximum/2 {
			delay = maximum
		} else {
			delay *= 2
		}
	}
	if delay > maximum {
		delay = maximum
	}
	if requested > delay {
		delay = requested
	}
	return delay
}

func (e *Engine) recordFeedFailure(ctx context.Context, configured config.FeedConfig, record state.FeedRecord, now time.Time, cause error, report *Report) error {
	category := feedFailureCategory(cause)
	delay := retryDelay(e.config.Schedule.Retry, record.ConsecutiveFailures, feed.RetryAfter(cause))
	if err := e.store.RecordFeedFailure(ctx, configured.Name, category, now, now.Add(delay)); err != nil {
		return syncError(ErrState, err)
	}
	report.FeedsFailed++
	if category == string(feed.ErrSuspiciousChange) {
		report.SuspiciousChanges++
	}
	report.Feeds = append(report.Feeds, FeedResult{Name: configured.Name, Status: FeedFailed, ErrorClass: category})
	return nil
}

func (e *Engine) Run(ctx context.Context, options RunOptions) (Report, error) {
	now := e.now().UTC()
	if now.IsZero() {
		return Report{}, syncError(ErrConfig, nil)
	}
	if !e.selectedFeedExists(options.FeedName) {
		return Report{}, syncError(ErrSelection, nil)
	}
	if options.DryRun {
		return e.runDry(ctx, options, now)
	}
	definitions, err := feedDefinitions(e.config.Feeds)
	if err != nil {
		return Report{}, syncError(ErrConfig, err)
	}
	previousRecords, err := e.store.ListFeeds(ctx)
	if err != nil {
		return Report{}, syncError(ErrState, err)
	}
	previousByName := make(map[string]state.FeedRecord, len(previousRecords))
	for _, record := range previousRecords {
		previousByName[record.Name] = record
	}
	definitionChanged := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		previous, exists := previousByName[definition.Name]
		definitionChanged[definition.Name] = !exists || previous.URLHash != definition.URLHash || previous.DefinitionHash != definition.DefinitionHash || previous.Enabled != definition.Enabled
	}
	records, err := e.store.EnsureFeeds(ctx, definitions, now)
	if err != nil {
		return Report{}, syncError(ErrState, err)
	}
	byName := make(map[string]state.FeedRecord, len(records))
	feedOrder := make(map[int64]int, len(records))
	for index, record := range records {
		byName[record.Name] = record
		feedOrder[record.ID] = index
	}
	report := Report{Feeds: make([]FeedResult, 0, len(e.config.Feeds))}
	for _, configured := range e.config.Feeds {
		if !configured.Enabled || (options.FeedName != "" && options.FeedName != configured.Name) {
			continue
		}
		record := byName[configured.Name]
		changed := definitionChanged[configured.Name]
		if !changed && ((record.LastSuccess != nil && now.Before(record.LastSuccess.Add(configured.MinUpdateInterval.Duration()))) ||
			(record.NextAttempt != nil && now.Before(*record.NextAttempt))) {
			report.FeedsNotDue++
			report.Feeds = append(report.Feeds, FeedResult{Name: configured.Name, Status: FeedNotDue})
			continue
		}
		etag, lastModified := record.ETag, record.LastModified
		validationRecord := record
		if changed {
			etag, lastModified = "", ""
			validationRecord.AcceptedEntries = 0
		}
		result, err := e.fetcher.Fetch(ctx, feed.FetchRequest{
			URL: configured.URL, Timeout: configured.Timeout.Duration(), MaxBytes: configured.MaxDownloadBytes,
			ContentTypes: configured.ContentTypes, ETag: etag, LastModified: lastModified,
		})
		if err != nil {
			if stateErr := e.recordFeedFailure(ctx, configured, record, now, err, &report); stateErr != nil {
				return report, stateErr
			}
			continue
		}
		if result.NotModified && changed {
			result.Destroy()
			if stateErr := e.recordFeedFailure(ctx, configured, record, now, errUnsolicitedNotModified, &report); stateErr != nil {
				return report, stateErr
			}
			continue
		}
		if result.NotModified {
			result.Destroy()
			if err := e.store.RecordFeedNotModified(ctx, configured.Name, result.ETag, result.LastModified, now); err != nil {
				return report, syncError(ErrState, err)
			}
			report.FeedsUnchanged++
			report.Feeds = append(report.Feeds, FeedResult{Name: configured.Name, Status: FeedUnchanged, Accepted: record.AcceptedEntries, Rejected: record.RejectedEntries})
			continue
		}
		snapshot, rejected, validationErr := e.parseFetched(configured, validationRecord, result, now)
		result.Destroy()
		if validationErr != nil {
			if stateErr := e.recordFeedFailure(ctx, configured, record, now, validationErr, &report); stateErr != nil {
				return report, stateErr
			}
			continue
		}
		if _, err := e.store.ApplyFeedSnapshot(ctx, configured.Name, state.FeedSnapshot{
			Version: snapshot.Version, ETag: result.ETag, LastModified: result.LastModified,
			Entries: snapshot.Entries, Rejected: rejected,
		}, e.config.Decisions.MissingGraceRuns, now); err != nil {
			return report, syncError(ErrState, err)
		}
		report.FeedsSucceeded++
		report.Feeds = append(report.Feeds, FeedResult{Name: configured.Name, Status: FeedSucceeded, Accepted: len(snapshot.Entries), Rejected: rejected})
	}
	reconcileReport, err := e.reconciler.Run(ctx, reconcile.RunOptions{
		Allowlists: configuredAllowlists(e.config.Allowlists.CIDRs), FeedOrder: feedOrder,
	})
	report.Reconcile = reconcileReport
	if err != nil {
		return report, syncError(ErrReconcile, err)
	}
	if report.FeedsFailed > 0 {
		return report, syncError(ErrDegraded, nil)
	}
	return report, nil
}
