package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
	"crowdshield/internal/ops"
)

func TestListFeedsSortsAndBoundsState(t *testing.T) {
	at := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	feeds := []FeedStatus{
		{Name: "feed-two", Enabled: false},
		{Name: "feed-one", Enabled: true, LastSuccess: at, ConsecutiveFailures: 2, LastFailure: ops.FailureFeedDownload},
	}
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions:    Actions{ListFeeds: func(context.Context, config.Config) ([]FeedStatus, error) { return feeds, nil }},
	}
	for _, args := range [][]string{{"list-feeds"}, {"list-feeds", "--json"}} {
		var stdout, stderr bytes.Buffer
		if code := Execute(context.Background(), args, &stdout, &stderr, options); code != ExitSuccess || stderr.Len() != 0 {
			t.Fatalf("list-feeds failed: %v", args)
		}
		text := stdout.String()
		if strings.Index(text, "feed-one") > strings.Index(text, "feed-two") || strings.Contains(text, "http") || strings.Contains(text, "198.51.100") {
			t.Fatalf("feed output was nondeterministic or unsafe: %q", text)
		}
	}
}
