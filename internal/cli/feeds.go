package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"crowdshield/internal/config"
)

type feedStatusJSON struct {
	Name                string `json:"name"`
	Enabled             bool   `json:"enabled"`
	LastSuccess         string `json:"last_success,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastFailure         string `json:"last_failure,omitempty"`
}

func listFeedsCommand(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	flags := commandFlags("list-feeds")
	path := flags.String("config", config.DefaultPath, "configuration file")
	asJSON := flags.Bool("json", false, "emit JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || options.LoadConfig == nil {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	if options.Actions.ListFeeds == nil {
		_, _ = fmt.Fprintln(stderr, "feed status unavailable")
		return ExitOperational
	}
	feeds, err := options.Actions.ListFeeds(ctx, loaded)
	if err != nil || len(feeds) > 256 {
		_, _ = fmt.Fprintln(stderr, "feed status unavailable")
		return ExitOperational
	}
	feeds = append([]FeedStatus(nil), feeds...)
	sort.Slice(feeds, func(left, right int) bool { return feeds[left].Name < feeds[right].Name })
	seen := make(map[string]struct{}, len(feeds))
	for _, feed := range feeds {
		if feed.Validate() != nil {
			_, _ = fmt.Fprintln(stderr, "feed status unavailable")
			return ExitOperational
		}
		if _, exists := seen[feed.Name]; exists {
			_, _ = fmt.Fprintln(stderr, "feed status unavailable")
			return ExitOperational
		}
		seen[feed.Name] = struct{}{}
	}
	if *asJSON {
		output := make([]feedStatusJSON, 0, len(feeds))
		for _, feed := range feeds {
			item := feedStatusJSON{
				Name: feed.Name, Enabled: feed.Enabled, ConsecutiveFailures: feed.ConsecutiveFailures,
				LastFailure: string(feed.LastFailure),
			}
			if !feed.LastSuccess.IsZero() {
				item.LastSuccess = feed.LastSuccess.UTC().Format(time.RFC3339)
			}
			output = append(output, item)
		}
		if json.NewEncoder(stdout).Encode(output) != nil {
			return ExitOperational
		}
		return ExitSuccess
	}
	for _, feed := range feeds {
		_, _ = fmt.Fprintf(stdout, "name=%s enabled=%t consecutive_failures=%d", feed.Name, feed.Enabled, feed.ConsecutiveFailures)
		if !feed.LastSuccess.IsZero() {
			_, _ = fmt.Fprintf(stdout, " last_success=%s", feed.LastSuccess.UTC().Format(time.RFC3339))
		}
		if feed.LastFailure != "" {
			_, _ = fmt.Fprintf(stdout, " last_failure=%s", feed.LastFailure)
		}
		_, _ = fmt.Fprintln(stdout)
	}
	return ExitSuccess
}
