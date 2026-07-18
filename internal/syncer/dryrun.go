package syncer

import (
	"bytes"
	"context"
	"time"

	"crowdshield/internal/config"
	"crowdshield/internal/feed"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/state"
)

func (e *Engine) parseFetched(configured config.FeedConfig, record state.FeedRecord, result feed.FetchResult, now time.Time) (feed.Snapshot, int, error) {
	parsed, err := feed.Parse(feed.Format(configured.Format), bytes.NewReader(result.Body), feed.Limits{
		Family: feed.Family(configured.Family), MaxLineBytes: e.config.Validation.MaxLineBytes,
		MaxMalformedLines: configured.MaxMalformedLines, MaxMalformedRatio: configured.MaxMalformedRatio,
		RequireFinalNewline: configured.RequireFinalNewline,
	})
	if err != nil {
		return feed.Snapshot{}, 0, err
	}
	snapshot, err := feed.Validate(parsed, feed.ValidationPolicy{
		ExpectedMinEntries: configured.ExpectedMinEntries, ExpectedMaxEntries: configured.ExpectedMaxEntries,
		MaxGrowthRatio: configured.MaxGrowthRatio, MaxShrinkRatio: configured.MaxShrinkRatio,
		PreviousAcceptedEntries: record.AcceptedEntries, Now: now,
		MaxMetadataAge: metadataAge(feed.Format(configured.Format)), MaxFutureSkew: 10 * time.Minute,
	})
	if err != nil {
		return feed.Snapshot{}, 0, err
	}
	return snapshot, parsed.Malformed + snapshot.RejectedSafety + snapshot.Duplicates, nil
}

func (e *Engine) selectedFeedExists(name string) bool {
	if name == "" {
		return true
	}
	for _, configured := range e.config.Feeds {
		if configured.Name == name {
			return true
		}
	}
	return false
}

func (e *Engine) runDry(ctx context.Context, options RunOptions, now time.Time) (Report, error) {
	records, err := e.store.ListFeeds(ctx)
	if err != nil {
		return Report{}, syncError(ErrState, err)
	}
	entries, err := e.store.ListActiveEntries(ctx)
	if err != nil {
		return Report{}, syncError(ErrState, err)
	}
	byName := make(map[string]state.FeedRecord, len(records))
	var nextID int64 = 1
	for _, record := range records {
		byName[record.Name] = record
		if record.ID >= nextID {
			nextID = record.ID + 1
		}
	}
	enabled := make(map[string]struct{}, len(e.config.Feeds))
	feedOrder := make(map[int64]int, len(e.config.Feeds))
	definitionChanged := make(map[string]bool, len(e.config.Feeds))
	for index, configured := range e.config.Feeds {
		if !configured.Enabled {
			continue
		}
		enabled[configured.Name] = struct{}{}
		record, exists := byName[configured.Name]
		hash, hashErr := definitionHash(configured)
		if hashErr != nil {
			return Report{}, syncError(ErrConfig, hashErr)
		}
		definitionChanged[configured.Name] = !exists || record.URLHash != hashText(configured.URL) || record.DefinitionHash != hash || !record.Enabled
		if !exists {
			record = state.FeedRecord{ID: nextID, Name: configured.Name, Enabled: true}
			nextID++
			byName[configured.Name] = record
		}
		feedOrder[record.ID] = index
	}
	ephemeral := make([]state.StoredEntry, 0, len(entries))
	for _, entry := range entries {
		if _, exists := enabled[entry.FeedName]; exists {
			ephemeral = append(ephemeral, entry)
		}
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
		result, fetchErr := e.fetcher.Fetch(ctx, feed.FetchRequest{
			URL: configured.URL, Timeout: configured.Timeout.Duration(), MaxBytes: configured.MaxDownloadBytes,
			ContentTypes: configured.ContentTypes, ETag: etag, LastModified: lastModified,
		})
		if fetchErr != nil {
			e.recordDryFailure(configured, fetchErr, &report)
			continue
		}
		if result.NotModified && changed {
			result.Destroy()
			e.recordDryFailure(configured, errUnsolicitedNotModified, &report)
			continue
		}
		if result.NotModified {
			result.Destroy()
			report.FeedsUnchanged++
			report.Feeds = append(report.Feeds, FeedResult{Name: configured.Name, Status: FeedUnchanged, Accepted: record.AcceptedEntries, Rejected: record.RejectedEntries})
			continue
		}
		snapshot, rejected, validationErr := e.parseFetched(configured, validationRecord, result, now)
		result.Destroy()
		if validationErr != nil {
			e.recordDryFailure(configured, validationErr, &report)
			continue
		}
		kept := ephemeral[:0]
		for _, entry := range ephemeral {
			if entry.FeedName != configured.Name {
				kept = append(kept, entry)
			}
		}
		ephemeral = kept
		for _, item := range snapshot.Entries {
			ephemeral = append(ephemeral, state.StoredEntry{
				FeedID: record.ID, FeedName: configured.Name, Entry: item,
				FirstSeen: now, LastSeen: now, Active: true,
			})
		}
		report.FeedsSucceeded++
		report.Feeds = append(report.Feeds, FeedResult{Name: configured.Name, Status: FeedSucceeded, Accepted: len(snapshot.Entries), Rejected: rejected})
	}
	reconcileReport, err := e.reconciler.Run(ctx, reconcile.RunOptions{
		Allowlists: configuredAllowlists(e.config.Allowlists.CIDRs), FeedOrder: feedOrder,
		DryRun: true, OverrideEntries: true, Entries: ephemeral,
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

func (e *Engine) recordDryFailure(configured config.FeedConfig, cause error, report *Report) {
	category := feedFailureCategory(cause)
	report.FeedsFailed++
	if category == string(feed.ErrSuspiciousChange) {
		report.SuspiciousChanges++
	}
	report.Feeds = append(report.Feeds, FeedResult{Name: configured.Name, Status: FeedFailed, ErrorClass: category})
}
