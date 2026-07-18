package app

import (
	"context"
	"errors"
	"time"

	"crowdshield/internal/feed"
	"crowdshield/internal/lapi"
	"crowdshield/internal/ops"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/syncer"
)

var ErrInvalidSyncReport = errors.New("invalid synchronization report")

const maxOperationalCount = int64(100_000_000)

func boundedInt(value int) (int64, bool) {
	converted := int64(value)
	return converted, value >= 0 && converted <= maxOperationalCount
}

func addBounded(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > maxOperationalCount-right {
		return 0, false
	}
	return left + right, true
}

func feedFailure(errorClass string) (ops.FailureCategory, bool) {
	switch feed.ErrorCategory(errorClass) {
	case feed.ErrRequest, feed.ErrSSRF, feed.ErrRedirect, feed.ErrHTTPStatus,
		feed.ErrBodySize, feed.ErrContentType, feed.ErrHTML, feed.ErrResponseHeader:
		return ops.FailureFeedDownload, true
	case feed.ErrFormat, feed.ErrPolicy, feed.ErrEmpty, feed.ErrLineTooLong,
		feed.ErrTruncated, feed.ErrMetadata, feed.ErrMalformedThreshold,
		feed.ErrEntryCount, feed.ErrSuspiciousChange:
		return ops.FailureFeedValidation, false
	default:
		return ops.FailureRuntime, false
	}
}

func operationalFeedResult(input syncer.FeedResult) (ops.FeedResult, error) {
	accepted, acceptedOK := boundedInt(input.Accepted)
	rejected, rejectedOK := boundedInt(input.Rejected)
	if !acceptedOK || !rejectedOK {
		return ops.FeedResult{}, ErrInvalidSyncReport
	}
	result := ops.FeedResult{Name: input.Name, Accepted: accepted, Rejected: rejected}
	switch input.Status {
	case syncer.FeedSucceeded:
		result.Outcome = ops.OutcomeSuccess
		if input.ErrorClass != "" {
			return ops.FeedResult{}, ErrInvalidSyncReport
		}
	case syncer.FeedUnchanged:
		result.Outcome = ops.OutcomeNotModified
		if input.ErrorClass != "" {
			return ops.FeedResult{}, ErrInvalidSyncReport
		}
	case syncer.FeedNotDue:
		result.Outcome = ops.OutcomeNotDue
		if input.ErrorClass != "" {
			return ops.FeedResult{}, ErrInvalidSyncReport
		}
	case syncer.FeedFailed:
		result.Outcome = ops.OutcomeFailed
		result.Failure, _ = feedFailure(input.ErrorClass)
	default:
		return ops.FeedResult{}, ErrInvalidSyncReport
	}
	if result.Validate() != nil {
		return ops.FeedResult{}, ErrInvalidSyncReport
	}
	return result, nil
}

func classifyFailure(err error, feeds []ops.FeedResult) (ops.FailureCategory, bool) {
	if errors.Is(err, context.Canceled) {
		return ops.FailureCancelled, false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ops.FailureTimeout, true
	}
	if syncer.IsCategory(err, syncer.ErrConfig) || syncer.IsCategory(err, syncer.ErrSelection) {
		return ops.FailureConfig, false
	}
	if syncer.IsCategory(err, syncer.ErrState) {
		return ops.FailureDatabase, true
	}
	if syncer.IsCategory(err, syncer.ErrDegraded) {
		failure := ops.FailureRuntime
		retryable := false
		for _, item := range feeds {
			if item.Outcome != ops.OutcomeFailed && item.Outcome != ops.OutcomeDegraded {
				continue
			}
			if item.Failure == ops.FailureFeedValidation {
				failure = ops.FailureFeedValidation
			} else if failure != ops.FailureFeedValidation && item.Failure == ops.FailureFeedDownload {
				failure = ops.FailureFeedDownload
			}
			if item.Failure == ops.FailureFeedDownload {
				retryable = true
			}
		}
		return failure, retryable
	}
	if lapi.IsCategory(err, lapi.ErrAuth) {
		return ops.FailureLAPIAuth, false
	}
	if reconcile.IsCategory(err, reconcile.ErrState) {
		return ops.FailureDatabase, true
	}
	if reconcile.IsCategory(err, reconcile.ErrOwnership) {
		return ops.FailureOwnership, false
	}
	if reconcile.IsCategory(err, reconcile.ErrLAPI) ||
		lapi.IsCategory(err, lapi.ErrRequest) || lapi.IsCategory(err, lapi.ErrStatus) ||
		lapi.IsCategory(err, lapi.ErrResponseSize) || lapi.IsCategory(err, lapi.ErrContentType) ||
		lapi.IsCategory(err, lapi.ErrDecode) || lapi.IsCategory(err, lapi.ErrNotFound) {
		return ops.FailureLAPI, true
	}
	if reconcile.IsCategory(err, reconcile.ErrBusy) {
		return ops.FailureRuntime, true
	}
	return ops.FailureRuntime, false
}

// ResultFromSync is the privacy boundary between synchronization internals and
// operations. It deliberately never retains or returns the supplied raw error.
func ResultFromSync(report syncer.Report, runErr error, startedAt, completedAt time.Time, activeDecisions int) (ops.Result, error) {
	counts := ops.Counts{}
	var ok bool
	if counts.FeedsSucceeded, ok = boundedInt(report.FeedsSucceeded); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.FeedsFailed, ok = boundedInt(report.FeedsFailed); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.FeedsUnchanged, ok = boundedInt(report.FeedsUnchanged); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.FeedsNotDue, ok = boundedInt(report.FeedsNotDue); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.Added, ok = boundedInt(report.Reconcile.Added); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.Refreshed, ok = boundedInt(report.Reconcile.Refreshed); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.Removed, ok = boundedInt(report.Reconcile.Removed); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.Skipped, ok = boundedInt(report.Reconcile.Skipped); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.LAPIRequests, ok = boundedInt(report.Reconcile.LAPIRequests); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	if counts.ActiveDecisions, ok = boundedInt(activeDecisions); !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	reconcileRejected, ok := boundedInt(report.Reconcile.Rejected)
	if !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	feeds := make([]ops.FeedResult, 0, len(report.Feeds))
	var derivedSucceeded, derivedFailed, derivedUnchanged, derivedNotDue, suspicious int64
	feedRejected := int64(0)
	for _, input := range report.Feeds {
		item, err := operationalFeedResult(input)
		if err != nil {
			return ops.Result{}, ErrInvalidSyncReport
		}
		feeds = append(feeds, item)
		switch item.Outcome {
		case ops.OutcomeSuccess:
			derivedSucceeded++
		case ops.OutcomeNotModified:
			derivedUnchanged++
		case ops.OutcomeNotDue:
			derivedNotDue++
		case ops.OutcomeFailed:
			derivedFailed++
			if feed.ErrorCategory(input.ErrorClass) == feed.ErrSuspiciousChange {
				suspicious++
			}
		}
		feedRejected, ok = addBounded(feedRejected, item.Rejected)
		if !ok {
			return ops.Result{}, ErrInvalidSyncReport
		}
	}
	expectedSuspicious, ok := boundedInt(report.SuspiciousChanges)
	if !ok || derivedSucceeded != counts.FeedsSucceeded || derivedFailed != counts.FeedsFailed ||
		derivedUnchanged != counts.FeedsUnchanged || derivedNotDue != counts.FeedsNotDue || suspicious != expectedSuspicious {
		return ops.Result{}, ErrInvalidSyncReport
	}
	counts.Rejected, ok = addBounded(feedRejected, reconcileRejected)
	if !ok {
		return ops.Result{}, ErrInvalidSyncReport
	}
	result := ops.Result{StartedAt: startedAt, CompletedAt: completedAt, Counts: counts, Feeds: feeds}
	switch {
	case runErr == nil:
		if report.FeedsFailed != 0 {
			return ops.Result{}, ErrInvalidSyncReport
		}
		result.Outcome = ops.OutcomeSuccess
	case errors.Is(runErr, context.Canceled):
		result.Outcome = ops.OutcomeCancelled
		result.Failure = ops.FailureCancelled
	default:
		result.Failure, result.Retryable = classifyFailure(runErr, feeds)
		if syncer.IsCategory(runErr, syncer.ErrDegraded) {
			result.Outcome = ops.OutcomeDegraded
		} else {
			result.Outcome = ops.OutcomeFailed
		}
	}
	if result.Validate() != nil {
		return ops.Result{}, ErrInvalidSyncReport
	}
	return result, nil
}
