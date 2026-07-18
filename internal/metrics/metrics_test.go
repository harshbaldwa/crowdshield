package metrics

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/ops"
)

var requiredMetricNames = []string{
	"crowdshield_build_info",
	"crowdshield_last_sync_attempt_timestamp_seconds",
	"crowdshield_last_sync_success_timestamp_seconds",
	"crowdshield_sync_duration_seconds",
	"crowdshield_sync_runs_total",
	"crowdshield_sync_failures_total",
	"crowdshield_feed_last_success_timestamp_seconds",
	"crowdshield_feed_entries",
	"crowdshield_feed_download_failures_total",
	"crowdshield_feed_validation_failures_total",
	"crowdshield_active_decisions",
	"crowdshield_decisions_added_total",
	"crowdshield_decisions_refreshed_total",
	"crowdshield_decisions_removed_total",
	"crowdshield_entries_rejected_total",
	"crowdshield_lapi_requests_total",
	"crowdshield_lapi_failures_total",
	"crowdshield_database_failures_total",
	"crowdshield_notifications_total",
}

func metricResult(started time.Time, added int64, feedAccepted int64) ops.Result {
	return ops.Result{
		Outcome: ops.OutcomeSuccess, StartedAt: started, CompletedAt: started.Add(2 * time.Second),
		Counts: ops.Counts{
			FeedsSucceeded: 1, Added: added, Refreshed: 3, Removed: 1,
			Rejected: 1, LAPIRequests: 4,
		},
		Feeds: []ops.FeedResult{{Name: "feed-one", Outcome: ops.OutcomeSuccess, Accepted: feedAccepted, Rejected: 1}},
	}
}

func render(t *testing.T, registry *Registry) string {
	t.Helper()
	var output bytes.Buffer
	if err := registry.WritePrometheus(&output); err != nil {
		t.Fatal("metrics exposition failed")
	}
	return output.String()
}

func TestRegistryExposesRequiredMetricsAndKeepsDryRunSeparate(t *testing.T) {
	registry, err := New(Options{
		Build: buildinfo.Info{
			Name: "crowdshield", Version: "dev", Revision: "unknown",
			BuildDate: "unknown", GoVersion: "go1.26.5", GOOS: "linux", GOARCH: "amd64",
		},
		Feeds: []string{"feed-one", "feed-two"},
	})
	if err != nil {
		t.Fatal("valid metrics registry rejected")
	}
	enforcedAt := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if err := registry.ObserveSync(ModeEnforce, metricResult(enforcedAt, 2, 10)); err != nil {
		t.Fatal("valid enforced result rejected")
	}
	dryRunAt := enforcedAt.Add(time.Hour)
	if err := registry.ObserveSync(ModeDryRun, metricResult(dryRunAt, 99, 99)); err != nil {
		t.Fatal("valid dry-run result rejected")
	}
	if err := registry.SetActiveDecisions(7); err != nil {
		t.Fatal("valid active decision count rejected")
	}
	body := render(t, registry)
	for _, name := range requiredMetricNames {
		if !strings.Contains(body, "# TYPE "+name+" ") {
			t.Fatal("required metric missing from exposition")
		}
	}
	if !strings.Contains(body, `crowdshield_sync_runs_total{mode="enforce",outcome="success"} 1`) ||
		!strings.Contains(body, `crowdshield_sync_runs_total{mode="dry_run",outcome="success"} 1`) {
		t.Fatal("sync mode/outcome counters are inaccurate")
	}
	if !strings.Contains(body, "crowdshield_decisions_added_total 2") ||
		strings.Contains(body, "crowdshield_decisions_added_total 101") {
		t.Fatal("dry-run plans changed enforcement counters")
	}
	if !strings.Contains(body, `crowdshield_feed_entries{feed="feed-one"} 10`) ||
		strings.Contains(body, `crowdshield_feed_entries{feed="feed-one"} 99`) {
		t.Fatal("dry-run changed durable feed gauges")
	}
	if !strings.Contains(body, "crowdshield_active_decisions 7") {
		t.Fatal("active decision gauge is inaccurate")
	}
	if !strings.Contains(body, `crowdshield_sync_duration_seconds{mode="enforce"} 2`) ||
		!strings.Contains(body, `crowdshield_sync_duration_seconds{mode="dry_run"} 2`) {
		t.Fatal("sync duration gauges are inaccurate")
	}
	if strings.Count(body, "# TYPE crowdshield_build_info gauge") != 1 {
		t.Fatal("metric descriptors were registered more than once")
	}
}

func TestRegistryRejectsUnboundedCardinalityAndSanitizesBuildLabels(t *testing.T) {
	canaries := []string{
		"198.51.100.23",
		"2001:db8::23/128",
		"https://feed.example.invalid/private",
		"password-canary-do-not-emit",
		"token-canary-do-not-emit",
		"eyJhbGciOiJIUzI1NiJ9.canary.signature",
	}
	for _, feedName := range canaries[:3] {
		if _, err := New(Options{Build: buildinfo.Current(), Feeds: []string{feedName}}); err == nil {
			t.Fatal("unsafe metric feed label accepted")
		}
	}
	registry, err := New(Options{
		Build: buildinfo.Info{Name: canaries[3], Version: canaries[4], Revision: canaries[5], GoVersion: canaries[2], GOOS: "linux", GOARCH: "amd64"},
		Feeds: []string{"feed-one"},
	})
	if err != nil {
		t.Fatal("unsafe build labels should be sanitized rather than fail startup")
	}
	invalidEvent := ops.Event{
		Code: ops.CodeFeedResult, Operation: ops.OperationFeed, Feed: canaries[0],
		Outcome: ops.OutcomeFailed, Failure: ops.FailureFeedDownload,
		Severity: ops.SeverityWarning, At: time.Now(),
	}
	if err := registry.ApplyEvent(invalidEvent); err == nil {
		t.Fatal("unsafe operational event entered metrics")
	}
	body := render(t, registry)
	for _, canary := range canaries {
		if strings.Contains(body, canary) {
			t.Fatal("sensitive or unbounded value appeared in metrics")
		}
	}
	if _, err := New(Options{Build: buildinfo.Current(), Feeds: []string{"feed-one", "feed-one"}}); err == nil {
		t.Fatal("duplicate feed label registration accepted")
	}
	tooMany := make([]string, 257)
	for index := range tooMany {
		tooMany[index] = "feed-" + strings.Repeat("a", index%50+1)
	}
	if _, err := New(Options{Build: buildinfo.Current(), Feeds: tooMany}); err == nil {
		t.Fatal("unbounded feed cardinality accepted")
	}
}

func TestRegistryUpdatesAndExpositionAreConcurrencySafe(t *testing.T) {
	first, err := New(Options{Build: buildinfo.Current(), Feeds: []string{"feed-one"}})
	if err != nil {
		t.Fatal("first independent registry failed")
	}
	if _, err := New(Options{Build: buildinfo.Current(), Feeds: []string{"feed-one"}}); err != nil {
		t.Fatal("duplicate independent registry construction failed")
	}
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func(offset int) {
			defer workers.Done()
			result := metricResult(started.Add(time.Duration(offset)*time.Second), 1, int64(offset+1))
			if err := first.ObserveSync(ModeEnforce, result); err != nil {
				t.Error("concurrent sync observation failed")
			}
			if err := first.ApplyEvent(ops.Event{
				Code: ops.CodeNotificationResult, Operation: ops.OperationNotification,
				Outcome: ops.OutcomeSuccess, Severity: ops.SeverityInfo,
				At: started.Add(time.Duration(offset) * time.Second),
			}); err != nil {
				t.Error("concurrent event observation failed")
			}
			if err := first.SetActiveDecisions(int64(offset)); err != nil {
				t.Error("concurrent gauge update failed")
			}
			var sink bytes.Buffer
			if err := first.WritePrometheus(&sink); err != nil {
				t.Error("concurrent exposition failed")
			}
		}(index)
	}
	workers.Wait()
	body := render(t, first)
	if !strings.Contains(body, `crowdshield_sync_runs_total{mode="enforce",outcome="success"} 32`) ||
		!strings.Contains(body, `crowdshield_notifications_total{outcome="success"} 32`) {
		t.Fatal("concurrent counters lost updates")
	}
	first.Observe(context.Background(), ops.Event{
		Code: ops.CodeNotificationResult, Operation: ops.OperationNotification,
		Outcome: ops.OutcomeSuccess, Severity: ops.SeverityInfo, At: started,
	})
}

func validatePrometheusText(t *testing.T, body string) {
	t.Helper()
	metricName := regexp.MustCompile(`^[A-Za-z_:][A-Za-z0-9_:]*$`)
	labelPair := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*="(?:[^"\\]|\\.)*"$`)
	types := make(map[string]struct{})
	help := make(map[string]struct{})
	series := make(map[string]struct{})
	if !strings.HasSuffix(body, "\n") {
		t.Fatal("Prometheus exposition is not newline terminated")
	}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			parts := strings.SplitN(line, " ", 4)
			if len(parts) != 4 || !metricName.MatchString(parts[2]) || parts[3] == "" {
				t.Fatal("invalid Prometheus HELP line")
			}
			if _, duplicate := help[parts[2]]; duplicate {
				t.Fatal("duplicate Prometheus HELP descriptor")
			}
			help[parts[2]] = struct{}{}
		case strings.HasPrefix(line, "# TYPE "):
			parts := strings.Fields(line)
			if len(parts) != 4 || !metricName.MatchString(parts[2]) || (parts[3] != "gauge" && parts[3] != "counter") {
				t.Fatal("invalid Prometheus TYPE line")
			}
			if _, duplicate := types[parts[2]]; duplicate {
				t.Fatal("duplicate Prometheus TYPE descriptor")
			}
			types[parts[2]] = struct{}{}
		default:
			separator := strings.LastIndexByte(line, ' ')
			if separator <= 0 {
				t.Fatal("invalid Prometheus sample")
			}
			identity, value := line[:separator], line[separator+1:]
			if _, err := strconv.ParseFloat(value, 64); err != nil {
				t.Fatal("invalid Prometheus sample value")
			}
			name := identity
			if opening := strings.IndexByte(identity, '{'); opening >= 0 {
				if !strings.HasSuffix(identity, "}") {
					t.Fatal("unterminated Prometheus label set")
				}
				name = identity[:opening]
				labels := identity[opening+1 : len(identity)-1]
				for _, pair := range strings.Split(labels, ",") {
					if !labelPair.MatchString(pair) {
						t.Fatal("invalid Prometheus label pair")
					}
				}
			}
			if !metricName.MatchString(name) {
				t.Fatal("invalid Prometheus metric name")
			}
			if _, declared := types[name]; !declared {
				t.Fatal("sample appeared before or without TYPE descriptor")
			}
			if _, duplicate := series[identity]; duplicate {
				t.Fatal("duplicate Prometheus time series")
			}
			series[identity] = struct{}{}
		}
	}
	if len(types) != len(requiredMetricNames) || len(help) != len(requiredMetricNames) {
		t.Fatal("Prometheus descriptors are incomplete")
	}
}

func TestHTTPExpositionIsValidDeterministicPrometheusText(t *testing.T) {
	registry, err := New(Options{Build: buildinfo.Current(), Feeds: []string{"feed-one", "feed-two"}})
	if err != nil {
		t.Fatal("valid HTTP metrics registry rejected")
	}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	registry.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal("metrics handler did not return success")
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatal("metrics handler returned the wrong content type")
	}
	first := response.Body.String()
	validatePrometheusText(t, first)
	if second := render(t, registry); second != first {
		t.Fatal("unchanged metrics exposition was not deterministic")
	}

	unsupported := httptest.NewRecorder()
	registry.ServeHTTP(unsupported, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if unsupported.Code != http.StatusMethodNotAllowed {
		t.Fatal("metrics handler accepted an unsupported method")
	}
}

func TestFailedSyncPreservesLastKnownActiveDecisionGauge(t *testing.T) {
	registry, err := New(Options{Build: buildinfo.Current(), Feeds: []string{"feed-one"}})
	if err != nil {
		t.Fatal("valid active-decision registry rejected")
	}
	if err := registry.SetActiveDecisions(7); err != nil {
		t.Fatal("valid initial active decision count rejected")
	}
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	failed := ops.Result{
		Outcome: ops.OutcomeFailed, Failure: ops.FailureLAPI, Retryable: true,
		StartedAt: started, CompletedAt: started.Add(time.Second),
	}
	if err := registry.ObserveSync(ModeEnforce, failed); err != nil {
		t.Fatal("valid failed sync observation rejected")
	}
	if body := render(t, registry); !strings.Contains(body, "crowdshield_active_decisions 7") {
		t.Fatal("failed synchronization erased the last known active decision gauge")
	}
}
