package app

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sort"
	"time"

	"crowdshield/internal/cli"
	"crowdshield/internal/config"
	"crowdshield/internal/feed"
	"crowdshield/internal/network"
	"crowdshield/internal/ops"
	"crowdshield/internal/state"
)

var ErrOperatorStatus = errors.New("operator status failed")
var ErrOperatorFeeds = errors.New("operator feed status failed")
var ErrOperatorExplain = errors.New("operator explanation failed")

type operatorStatusOptions struct {
	Now func() time.Time
}

func databaseUnavailableStatus() cli.Status {
	return cli.Status{Reason: cli.StatusDatabase}
}

func syncOutcome(status state.RunStatus) ops.Outcome {
	switch status {
	case state.RunStatusSuccess:
		return ops.OutcomeSuccess
	case state.RunStatusDegraded:
		return ops.OutcomeDegraded
	case state.RunStatusFailed:
		return ops.OutcomeFailed
	case state.RunStatusCancelled:
		return ops.OutcomeCancelled
	default:
		return ""
	}
}

func statusCLIWithOptions(ctx context.Context, cfg config.Config, options operatorStatusOptions) (cli.Status, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	now := options.Now().UTC()
	if ctx == nil || now.IsZero() || cfg.Validate() != nil {
		return cli.Status{}, ErrOperatorStatus
	}
	store, err := state.OpenReadOnly(ctx, state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		IntegrityCheck: cfg.Database.IntegrityCheckOnStart,
	})
	if err != nil {
		return databaseUnavailableStatus(), nil
	}

	lastSafe, foundSafe, safeErr := store.RuntimeTimestamp(ctx, state.RuntimeLastSafeSync)
	runs, runsErr := store.ListSyncRuns(ctx, 1)
	active, activeErr := store.ListActiveDecisions(ctx)
	closeErr := store.Close()
	if safeErr != nil || runsErr != nil || activeErr != nil || closeErr != nil {
		return databaseUnavailableStatus(), nil
	}

	result := cli.Status{
		Reason: cli.StatusSyncPending, LastSafeSync: lastSafe,
		ActiveDecisions: int64(len(active)),
	}
	if len(runs) == 1 {
		result.LastOutcome = syncOutcome(runs[0].Status)
		result.LastFailure = runs[0].Failure
	}
	if !foundSafe {
		return result, nil
	}
	if now.Sub(lastSafe) > cfg.Server.ReadinessMaxSyncAge.Duration() {
		result.Reason = cli.StatusSyncStale
		return result, nil
	}
	result.Ready = true
	result.Reason = cli.StatusReady
	return result, nil
}

// StatusCLI derives bounded readiness from read-only persisted state. It never
// loads credentials, contacts LAPI, applies migrations, or creates a database.
func StatusCLI(ctx context.Context, cfg config.Config) (cli.Status, error) {
	return statusCLIWithOptions(ctx, cfg, operatorStatusOptions{})
}

func operatorFeedFailure(category string) (ops.FailureCategory, bool) {
	switch feed.ErrorCategory(category) {
	case feed.ErrRequest, feed.ErrSSRF, feed.ErrRedirect, feed.ErrHTTPStatus,
		feed.ErrBodySize, feed.ErrContentType, feed.ErrHTML, feed.ErrResponseHeader:
		return ops.FailureFeedDownload, true
	case feed.ErrFormat, feed.ErrPolicy, feed.ErrEmpty, feed.ErrLineTooLong,
		feed.ErrTruncated, feed.ErrMetadata, feed.ErrMalformedThreshold,
		feed.ErrEntryCount, feed.ErrSuspiciousChange:
		return ops.FailureFeedValidation, true
	default:
		return "", false
	}
}

func configuredFeedStatus(cfg config.Config) []cli.FeedStatus {
	result := make([]cli.FeedStatus, 0, len(cfg.Feeds))
	for _, configured := range cfg.Feeds {
		result = append(result, cli.FeedStatus{Name: configured.Name, Enabled: configured.Enabled})
	}
	return result
}

// ListFeedsCLI merges configured feed identity with bounded persisted health.
// It never returns feed URLs, cache validators, or content-derived values.
func ListFeedsCLI(ctx context.Context, cfg config.Config) ([]cli.FeedStatus, error) {
	if ctx == nil || cfg.Validate() != nil {
		return nil, ErrOperatorFeeds
	}
	result := configuredFeedStatus(cfg)
	store, err := state.OpenReadOnly(ctx, state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		IntegrityCheck: cfg.Database.IntegrityCheckOnStart,
	})
	if err != nil {
		if _, statErr := os.Stat(cfg.Database.Path); os.IsNotExist(statErr) {
			return result, nil
		}
		return nil, ErrOperatorFeeds
	}
	records, listErr := store.ListFeeds(ctx)
	closeErr := store.Close()
	if listErr != nil || closeErr != nil {
		return nil, ErrOperatorFeeds
	}
	byName := make(map[string]state.FeedRecord, len(records))
	for _, record := range records {
		byName[record.Name] = record
	}
	for index := range result {
		record, exists := byName[result[index].Name]
		if !exists {
			continue
		}
		if record.LastSuccess != nil {
			result[index].LastSuccess = record.LastSuccess.UTC()
		}
		result[index].ConsecutiveFailures = record.ConsecutiveFailures
		if result[index].ConsecutiveFailures > 100 {
			result[index].ConsecutiveFailures = 100
		}
		if record.ConsecutiveFailures > 0 {
			mapped, ok := operatorFeedFailure(record.LastErrorCategory)
			if !ok {
				return nil, ErrOperatorFeeds
			}
			result[index].LastFailure = mapped
		}
	}
	return result, nil
}

func prefixCovers(cover, target netip.Prefix) bool {
	return cover.IsValid() && target.IsValid() && cover.Addr().BitLen() == target.Addr().BitLen() &&
		cover.Bits() <= target.Bits() && cover.Contains(target.Addr())
}

func explainAllowlisted(target netip.Prefix, cfg config.Config) bool {
	for _, item := range cfg.Allowlists.CIDRs {
		if target.Overlaps(item.Prefix()) {
			return true
		}
	}
	return false
}

func decisionPrefix(record state.DecisionRecord) (netip.Prefix, error) {
	switch record.Scope {
	case network.ScopeIP:
		prefix, kind, err := network.ParseValue(record.Value)
		if err != nil || kind != network.KindIP {
			return netip.Prefix{}, ErrOperatorExplain
		}
		return prefix, nil
	case network.ScopeRange:
		prefix, kind, err := network.ParseValue(record.Value)
		if err != nil || kind != network.KindRange {
			return netip.Prefix{}, ErrOperatorExplain
		}
		return prefix, nil
	default:
		return netip.Prefix{}, ErrOperatorExplain
	}
}

// ExplainCLI explains one explicit address or prefix using bounded configured
// policy and read-only persisted intent/ownership state.
func ExplainCLI(ctx context.Context, cfg config.Config, input string) (cli.ExplainResult, error) {
	target, kind, err := network.ParseValue(input)
	if ctx == nil || err != nil || cfg.Validate() != nil {
		return cli.ExplainResult{}, ErrOperatorExplain
	}
	result := cli.ExplainResult{Canonical: target.String(), Kind: cli.ExplainRange}
	if kind == network.KindIP {
		result.Canonical = target.Addr().String()
		result.Kind = cli.ExplainIP
	}
	result.Allowlisted = explainAllowlisted(target, cfg)

	store, err := state.OpenReadOnly(ctx, state.Options{
		Path: cfg.Database.Path, BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		IntegrityCheck: cfg.Database.IntegrityCheckOnStart,
	})
	if err != nil {
		if _, statErr := os.Stat(cfg.Database.Path); os.IsNotExist(statErr) {
			return result, nil
		}
		return cli.ExplainResult{}, ErrOperatorExplain
	}
	objects, objectErr := store.ListEnforcementObjects(ctx)
	decisions, decisionErr := store.ListActiveDecisions(ctx)
	operations, operationErr := store.OpenOperations(ctx)
	closeErr := store.Close()
	if objectErr != nil || decisionErr != nil || operationErr != nil || closeErr != nil {
		return cli.ExplainResult{}, ErrOperatorExplain
	}

	exactIndex := -1
	coverIndex := -1
	for index := range objects {
		if objects[index].Prefix == target {
			exactIndex = index
			continue
		}
		if !objects[index].Desired || objects[index].Scope != network.ScopeRange || !prefixCovers(objects[index].Prefix, target) {
			continue
		}
		if coverIndex < 0 || objects[index].Prefix.Bits() > objects[coverIndex].Prefix.Bits() ||
			(objects[index].Prefix.Bits() == objects[coverIndex].Prefix.Bits() && objects[index].Prefix.Addr().Less(objects[coverIndex].Prefix.Addr())) {
			coverIndex = index
		}
	}
	sourceIndex := exactIndex
	if exactIndex >= 0 {
		result.Desired = objects[exactIndex].Desired
		result.Allowlisted = result.Allowlisted || objects[exactIndex].Suppression == network.SuppressedAllowlist
	}
	if coverIndex >= 0 {
		result.Covered = true
		result.CoveringPrefix = objects[coverIndex].Prefix.String()
		if sourceIndex < 0 {
			sourceIndex = coverIndex
		}
	} else if exactIndex >= 0 && objects[exactIndex].Suppression == network.SuppressedCovered {
		return cli.ExplainResult{}, ErrOperatorExplain
	}
	if sourceIndex >= 0 {
		seen := make(map[string]struct{}, len(objects[sourceIndex].Sources))
		for _, source := range objects[sourceIndex].Sources {
			if _, exists := seen[source.FeedName]; exists {
				continue
			}
			seen[source.FeedName] = struct{}{}
			result.Contributors = append(result.Contributors, source.FeedName)
		}
		sort.Strings(result.Contributors)
	}
	for _, decision := range decisions {
		ownedPrefix, prefixErr := decisionPrefix(decision)
		if prefixErr != nil {
			return cli.ExplainResult{}, ErrOperatorExplain
		}
		if prefixCovers(ownedPrefix, target) {
			result.Owned = true
			break
		}
	}
	objectByID := make(map[int64]state.EnforcementRecord, len(objects))
	for _, object := range objects {
		objectByID[object.ID] = object
	}
	for _, operation := range operations {
		if operation.Status != state.OperationAmbiguous {
			continue
		}
		for _, item := range operation.Items {
			object, exists := objectByID[item.ObjectID]
			if exists && prefixCovers(object.Prefix, target) {
				result.OwnershipConflict = true
				break
			}
		}
	}
	if result.Validate() != nil {
		return cli.ExplainResult{}, ErrOperatorExplain
	}
	return result, nil
}
