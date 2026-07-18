// Package metrics provides a fixed, bounded-cardinality Prometheus text
// exposition without a global registry or third-party metrics dependency.
package metrics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/ops"
)

var (
	ErrInvalidOptions     = errors.New("invalid metrics options")
	ErrInvalidObservation = errors.New("invalid metrics observation")
	buildLabelPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,63}$`)
)

const maxFeeds = 256
const maxGaugeCount = int64(100_000_000)

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeDryRun  Mode = "dry_run"
)

var (
	modes        = []Mode{ModeEnforce, ModeDryRun}
	syncOutcomes = []ops.Outcome{
		ops.OutcomeSuccess, ops.OutcomeDegraded, ops.OutcomeFailed, ops.OutcomeCancelled,
	}
	failureCategories = []ops.FailureCategory{
		ops.FailureConfig, ops.FailureCredential, ops.FailureFeedDownload,
		ops.FailureFeedValidation, ops.FailureLAPIAuth, ops.FailureLAPI,
		ops.FailureDatabase, ops.FailureNotification, ops.FailureOwnership,
		ops.FailureTimeout, ops.FailureCancelled, ops.FailureRuntime, ops.FailureInternal,
	}
	notificationOutcomes = []ops.Outcome{ops.OutcomeSuccess, ops.OutcomeFailed, ops.OutcomeDegraded}
)

type Options struct {
	Build buildinfo.Info
	Feeds []string
}

type feedState struct {
	lastSuccess        float64
	entries            int64
	downloadFailures   uint64
	validationFailures uint64
}

type Registry struct {
	mu sync.RWMutex

	build   buildinfo.Info
	feeds   []string
	feedSet map[string]struct{}
	feed    map[string]feedState

	lastSyncAttempt float64
	lastSyncSuccess float64
	duration        map[Mode]float64
	durationAt      map[Mode]time.Time
	syncRuns        map[string]uint64
	syncFailures    map[ops.FailureCategory]uint64

	activeDecisions  int64
	decisionsAdded   uint64
	decisionsFresh   uint64
	decisionsRemoved uint64
	entriesRejected  uint64

	lapiRequests     map[ops.Outcome]uint64
	lapiFailures     map[ops.FailureCategory]uint64
	databaseFailures uint64
	notifications    map[ops.Outcome]uint64
}

func safeBuildLabel(value string) string {
	if !buildLabelPattern.MatchString(value) {
		return "unknown"
	}
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"password", "token", "secret", "bearer", "jwt", "canary", "://"} {
		if strings.Contains(lower, forbidden) {
			return "unknown"
		}
	}
	if net.ParseIP(value) != nil {
		return "unknown"
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return "unknown"
	}
	parts := strings.Split(value, ".")
	if len(parts) == 3 && len(parts[0]) >= 8 && len(parts[1]) >= 8 && len(parts[2]) >= 8 {
		return "unknown"
	}
	return value
}

func sanitizeBuild(info buildinfo.Info) buildinfo.Info {
	return buildinfo.Info{
		Name:    "crowdshield",
		Version: safeBuildLabel(info.Version), Revision: safeBuildLabel(info.Revision),
		BuildDate: "unknown", GoVersion: safeBuildLabel(info.GoVersion),
		GOOS: safeBuildLabel(info.GOOS), GOARCH: safeBuildLabel(info.GOARCH),
	}
}

func New(options Options) (*Registry, error) {
	if len(options.Feeds) > maxFeeds {
		return nil, ErrInvalidOptions
	}
	feeds := append([]string(nil), options.Feeds...)
	sort.Strings(feeds)
	feedStates := make(map[string]feedState, len(feeds))
	feedSet := make(map[string]struct{}, len(feeds))
	for _, name := range feeds {
		if !ops.ValidFeedName(name) {
			return nil, ErrInvalidOptions
		}
		if _, exists := feedSet[name]; exists {
			return nil, ErrInvalidOptions
		}
		feedSet[name] = struct{}{}
		feedStates[name] = feedState{}
	}
	return &Registry{
		build: sanitizeBuild(options.Build), feeds: feeds, feedSet: feedSet, feed: feedStates,
		duration: make(map[Mode]float64, len(modes)), durationAt: make(map[Mode]time.Time, len(modes)),
		syncRuns: make(map[string]uint64), syncFailures: make(map[ops.FailureCategory]uint64),
		lapiRequests: make(map[ops.Outcome]uint64), lapiFailures: make(map[ops.FailureCategory]uint64),
		notifications: make(map[ops.Outcome]uint64),
	}, nil
}

func validMode(mode Mode) bool { return mode == ModeEnforce || mode == ModeDryRun }

func runKey(mode Mode, outcome ops.Outcome) string {
	return string(mode) + "\x00" + string(outcome)
}

func add(current uint64, value int64) uint64 {
	if value <= 0 {
		return current
	}
	increment := uint64(value)
	if math.MaxUint64-current < increment {
		return math.MaxUint64
	}
	return current + increment
}

func laterUnix(current float64, candidate time.Time) float64 {
	value := float64(candidate.UnixNano()) / float64(time.Second)
	if value > current {
		return value
	}
	return current
}

func safeSynchronization(result ops.Result) bool {
	if result.Outcome == ops.OutcomeSuccess {
		return true
	}
	return result.Outcome == ops.OutcomeDegraded &&
		(result.Failure == ops.FailureFeedDownload || result.Failure == ops.FailureFeedValidation)
}

func (r *Registry) ObserveSync(mode Mode, result ops.Result) error {
	if r == nil || !validMode(mode) || result.Validate() != nil {
		return ErrInvalidObservation
	}
	for _, feed := range result.Feeds {
		if _, exists := r.feedSet[feed.Name]; !exists {
			return ErrInvalidObservation
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSyncAttempt = laterUnix(r.lastSyncAttempt, result.StartedAt)
	if result.CompletedAt.After(r.durationAt[mode]) {
		r.duration[mode] = result.CompletedAt.Sub(result.StartedAt).Seconds()
		r.durationAt[mode] = result.CompletedAt
	}
	r.syncRuns[runKey(mode, result.Outcome)] = add(r.syncRuns[runKey(mode, result.Outcome)], 1)
	if mode == ModeDryRun {
		return nil
	}
	if safeSynchronization(result) {
		r.lastSyncSuccess = laterUnix(r.lastSyncSuccess, result.CompletedAt)
	}
	if result.Outcome == ops.OutcomeFailed || result.Outcome == ops.OutcomeDegraded {
		r.syncFailures[result.Failure] = add(r.syncFailures[result.Failure], 1)
	}
	for _, observation := range result.Feeds {
		state := r.feed[observation.Name]
		switch observation.Outcome {
		case ops.OutcomeSuccess:
			state.lastSuccess = laterUnix(state.lastSuccess, result.CompletedAt)
			state.entries = observation.Accepted
		case ops.OutcomeNotModified:
			state.lastSuccess = laterUnix(state.lastSuccess, result.CompletedAt)
		case ops.OutcomeFailed, ops.OutcomeDegraded:
			switch observation.Failure {
			case ops.FailureFeedDownload:
				state.downloadFailures = add(state.downloadFailures, 1)
			case ops.FailureFeedValidation:
				state.validationFailures = add(state.validationFailures, 1)
			}
		}
		r.feed[observation.Name] = state
	}
	r.decisionsAdded = add(r.decisionsAdded, result.Counts.Added)
	r.decisionsFresh = add(r.decisionsFresh, result.Counts.Refreshed)
	r.decisionsRemoved = add(r.decisionsRemoved, result.Counts.Removed)
	r.entriesRejected = add(r.entriesRejected, result.Counts.Rejected)
	r.lapiRequests[result.Outcome] = add(r.lapiRequests[result.Outcome], result.Counts.LAPIRequests)
	if safeSynchronization(result) {
		r.activeDecisions = result.Counts.ActiveDecisions
	}
	switch result.Failure {
	case ops.FailureLAPIAuth, ops.FailureLAPI, ops.FailureTimeout:
		r.lapiFailures[result.Failure] = add(r.lapiFailures[result.Failure], 1)
	case ops.FailureDatabase:
		r.databaseFailures = add(r.databaseFailures, 1)
	}
	return nil
}

func (r *Registry) SetActiveDecisions(value int64) error {
	if r == nil || value < 0 || value > maxGaugeCount {
		return ErrInvalidObservation
	}
	r.mu.Lock()
	r.activeDecisions = value
	r.mu.Unlock()
	return nil
}

func (r *Registry) ApplyEvent(event ops.Event) error {
	if r == nil || event.Validate() != nil {
		return ErrInvalidObservation
	}
	if event.Feed != "" {
		if _, exists := r.feedSet[event.Feed]; !exists {
			return ErrInvalidObservation
		}
	}
	if event.Code != ops.CodeNotificationResult {
		return nil
	}
	if event.Outcome != ops.OutcomeSuccess && event.Outcome != ops.OutcomeFailed && event.Outcome != ops.OutcomeDegraded {
		return ErrInvalidObservation
	}
	r.mu.Lock()
	r.notifications[event.Outcome] = add(r.notifications[event.Outcome], 1)
	r.mu.Unlock()
	return nil
}

// Observe implements operational-event observers. Invalid events are ignored;
// callers that need validation feedback should use ApplyEvent directly.
func (r *Registry) Observe(_ context.Context, event ops.Event) {
	_ = r.ApplyEvent(event)
}

type label struct {
	name  string
	value string
}

func escapeLabel(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"")
	return replacer.Replace(value)
}

func writeDescriptor(buffer *bytes.Buffer, name, metricType, help string) {
	fmt.Fprintf(buffer, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeSample(buffer *bytes.Buffer, name string, labels []label, value string) {
	buffer.WriteString(name)
	if len(labels) > 0 {
		buffer.WriteByte('{')
		for index, item := range labels {
			if index > 0 {
				buffer.WriteByte(',')
			}
			fmt.Fprintf(buffer, `%s="%s"`, item.name, escapeLabel(item.value))
		}
		buffer.WriteByte('}')
	}
	buffer.WriteByte(' ')
	buffer.WriteString(value)
	buffer.WriteByte('\n')
}

func floatValue(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}

func counterValue(value uint64) string { return strconv.FormatUint(value, 10) }

func (r *Registry) WritePrometheus(writer io.Writer) error {
	if r == nil || writer == nil {
		return ErrInvalidOptions
	}
	var buffer bytes.Buffer
	r.mu.RLock()

	writeDescriptor(&buffer, "crowdshield_build_info", "gauge", "Build identity for the running Crowdshield process.")
	writeSample(&buffer, "crowdshield_build_info", []label{
		{name: "version", value: r.build.Version}, {name: "revision", value: r.build.Revision},
		{name: "go_version", value: r.build.GoVersion}, {name: "goos", value: r.build.GOOS},
		{name: "goarch", value: r.build.GOARCH},
	}, "1")

	writeDescriptor(&buffer, "crowdshield_last_sync_attempt_timestamp_seconds", "gauge", "Unix timestamp of the latest synchronization attempt.")
	writeSample(&buffer, "crowdshield_last_sync_attempt_timestamp_seconds", nil, floatValue(r.lastSyncAttempt))
	writeDescriptor(&buffer, "crowdshield_last_sync_success_timestamp_seconds", "gauge", "Unix timestamp of the latest safe enforced synchronization.")
	writeSample(&buffer, "crowdshield_last_sync_success_timestamp_seconds", nil, floatValue(r.lastSyncSuccess))
	writeDescriptor(&buffer, "crowdshield_sync_duration_seconds", "gauge", "Duration of the latest synchronization by execution mode.")
	for _, mode := range modes {
		writeSample(&buffer, "crowdshield_sync_duration_seconds", []label{{name: "mode", value: string(mode)}}, floatValue(r.duration[mode]))
	}
	writeDescriptor(&buffer, "crowdshield_sync_runs_total", "counter", "Synchronization runs by bounded mode and outcome.")
	for _, mode := range modes {
		for _, outcome := range syncOutcomes {
			writeSample(&buffer, "crowdshield_sync_runs_total", []label{{name: "mode", value: string(mode)}, {name: "outcome", value: string(outcome)}}, counterValue(r.syncRuns[runKey(mode, outcome)]))
		}
	}
	writeDescriptor(&buffer, "crowdshield_sync_failures_total", "counter", "Enforced synchronization failures by bounded category.")
	for _, category := range failureCategories {
		writeSample(&buffer, "crowdshield_sync_failures_total", []label{{name: "category", value: string(category)}}, counterValue(r.syncFailures[category]))
	}

	writeDescriptor(&buffer, "crowdshield_feed_last_success_timestamp_seconds", "gauge", "Unix timestamp of the latest successful feed result.")
	for _, name := range r.feeds {
		writeSample(&buffer, "crowdshield_feed_last_success_timestamp_seconds", []label{{name: "feed", value: name}}, floatValue(r.feed[name].lastSuccess))
	}
	writeDescriptor(&buffer, "crowdshield_feed_entries", "gauge", "Accepted entries in current local feed state.")
	for _, name := range r.feeds {
		writeSample(&buffer, "crowdshield_feed_entries", []label{{name: "feed", value: name}}, strconv.FormatInt(r.feed[name].entries, 10))
	}
	writeDescriptor(&buffer, "crowdshield_feed_download_failures_total", "counter", "Feed download failures by configured feed.")
	for _, name := range r.feeds {
		writeSample(&buffer, "crowdshield_feed_download_failures_total", []label{{name: "feed", value: name}}, counterValue(r.feed[name].downloadFailures))
	}
	writeDescriptor(&buffer, "crowdshield_feed_validation_failures_total", "counter", "Feed validation failures by configured feed.")
	for _, name := range r.feeds {
		writeSample(&buffer, "crowdshield_feed_validation_failures_total", []label{{name: "feed", value: name}}, counterValue(r.feed[name].validationFailures))
	}

	writeDescriptor(&buffer, "crowdshield_active_decisions", "gauge", "Current Crowdshield-owned active decisions.")
	writeSample(&buffer, "crowdshield_active_decisions", nil, strconv.FormatInt(r.activeDecisions, 10))
	writeDescriptor(&buffer, "crowdshield_decisions_added_total", "counter", "Enforced decisions successfully added.")
	writeSample(&buffer, "crowdshield_decisions_added_total", nil, counterValue(r.decisionsAdded))
	writeDescriptor(&buffer, "crowdshield_decisions_refreshed_total", "counter", "Enforced decisions successfully refreshed.")
	writeSample(&buffer, "crowdshield_decisions_refreshed_total", nil, counterValue(r.decisionsFresh))
	writeDescriptor(&buffer, "crowdshield_decisions_removed_total", "counter", "Owned decisions safely removed.")
	writeSample(&buffer, "crowdshield_decisions_removed_total", nil, counterValue(r.decisionsRemoved))
	writeDescriptor(&buffer, "crowdshield_entries_rejected_total", "counter", "Feed entries rejected by enforced synchronization.")
	writeSample(&buffer, "crowdshield_entries_rejected_total", nil, counterValue(r.entriesRejected))

	writeDescriptor(&buffer, "crowdshield_lapi_requests_total", "counter", "LAPI requests attributed to enforced synchronization outcomes.")
	for _, outcome := range syncOutcomes {
		writeSample(&buffer, "crowdshield_lapi_requests_total", []label{{name: "outcome", value: string(outcome)}}, counterValue(r.lapiRequests[outcome]))
	}
	writeDescriptor(&buffer, "crowdshield_lapi_failures_total", "counter", "LAPI failures by bounded category.")
	for _, category := range failureCategories {
		writeSample(&buffer, "crowdshield_lapi_failures_total", []label{{name: "category", value: string(category)}}, counterValue(r.lapiFailures[category]))
	}
	writeDescriptor(&buffer, "crowdshield_database_failures_total", "counter", "Database failures observed by enforced synchronization.")
	writeSample(&buffer, "crowdshield_database_failures_total", nil, counterValue(r.databaseFailures))
	writeDescriptor(&buffer, "crowdshield_notifications_total", "counter", "Notification outcomes from the bounded operational event stream.")
	for _, outcome := range notificationOutcomes {
		writeSample(&buffer, "crowdshield_notifications_total", []label{{name: "outcome", value: string(outcome)}}, counterValue(r.notifications[outcome]))
	}

	r.mu.RUnlock()
	_, err := writer.Write(buffer.Bytes())
	return err
}

// ServeHTTP exposes this registry using Prometheus text format.
func (r *Registry) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method == http.MethodHead {
		writer.WriteHeader(http.StatusOK)
		return
	}
	if err := r.WritePrometheus(writer); err != nil {
		http.Error(writer, "metrics unavailable", http.StatusServiceUnavailable)
	}
}
