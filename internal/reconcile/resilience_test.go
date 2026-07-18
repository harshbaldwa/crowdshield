package reconcile

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/feed"
	"crowdshield/internal/lapi"
	"crowdshield/internal/network"
)

type selectiveFailureClient struct {
	inner    lapiClient
	failFeed string
}

func (c *selectiveFailureClient) CreateAlert(ctx context.Context, request lapi.CreateRequest) (int64, error) {
	if request.FeedName == c.failFeed {
		return 0, errors.New("synthetic LAPI failure")
	}
	return c.inner.CreateAlert(ctx, request)
}
func (c *selectiveFailureClient) GetAlert(ctx context.Context, id int64) (lapi.Alert, error) {
	return c.inner.GetAlert(ctx, id)
}
func (c *selectiveFailureClient) ExpireDecision(ctx context.Context, id int64) error {
	return c.inner.ExpireDecision(ctx, id)
}
func (c *selectiveFailureClient) FindOperation(ctx context.Context, feedName, token string) (lapi.Alert, bool, error) {
	return c.inner.FindOperation(ctx, feedName, token)
}

func TestOneFailedFeedBatchDoesNotBlockAnotherFeed(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	h.snapshot(t, "feed-two", []feed.Entry{entry("9.9.9.0/24", network.KindRange)})
	reconciler, err := New(Options{
		Store: h.store, LAPI: &selectiveFailureClient{inner: h.client, failFeed: "feed-one"},
		MachineID: "crowdshield-test", Duration: 25 * time.Hour, RefreshBefore: 12 * time.Hour,
		BatchSize: 100, Now: func() time.Time { return h.now }, Token: func() (string, error) {
			h.tokens++
			return strings.Repeat(strconv.FormatInt(int64(h.tokens+1), 10), 32), nil
		},
	})
	if err != nil {
		t.Fatal("unable to construct selective reconciler")
	}
	report, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)})
	if err == nil || !IsCategory(err, ErrLAPI) || report.Added != 1 {
		t.Fatal("partial feed failure result incorrect")
	}
	alerts := h.server.Alerts()
	if len(alerts) != 1 || alerts[0].Scenario != "crowdshield/feed-two" {
		t.Fatal("independent feed batch did not continue")
	}
}

func TestLAPIOutagePreservesOwnedState(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	reconciler := h.reconciler(t, 100)
	if _, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)}); err != nil {
		t.Fatal("initial reconcile failed")
	}
	h.server.Close()
	_, err := reconciler.Run(context.Background(), RunOptions{
		FeedOrder: feedOrder(h), Allowlists: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")},
	})
	if err == nil || !IsCategory(err, ErrLAPI) {
		t.Fatal("LAPI outage was not surfaced")
	}
	active, stateErr := h.store.ListActiveDecisions(context.Background())
	if stateErr != nil || len(active) != 1 {
		t.Fatal("LAPI outage changed prior owned state")
	}
}

type blockingClient struct {
	inner   lapiClient
	entered chan struct{}
	release chan struct{}
}

func (c *blockingClient) CreateAlert(ctx context.Context, request lapi.CreateRequest) (int64, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
		return c.inner.CreateAlert(ctx, request)
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (c *blockingClient) GetAlert(ctx context.Context, id int64) (lapi.Alert, error) {
	return c.inner.GetAlert(ctx, id)
}
func (c *blockingClient) ExpireDecision(ctx context.Context, id int64) error {
	return c.inner.ExpireDecision(ctx, id)
}
func (c *blockingClient) FindOperation(ctx context.Context, feedName, token string) (lapi.Alert, bool, error) {
	return c.inner.FindOperation(ctx, feedName, token)
}

func TestConcurrentRunFailsFastWithoutOverlap(t *testing.T) {
	h := newHarness(t)
	h.snapshot(t, "feed-one", []feed.Entry{entry("8.8.8.0/24", network.KindRange)})
	blocking := &blockingClient{inner: h.client, entered: make(chan struct{}, 1), release: make(chan struct{})}
	reconciler, err := New(Options{
		Store: h.store, LAPI: blocking, MachineID: "crowdshield-test", Duration: 25 * time.Hour,
		RefreshBefore: 12 * time.Hour, BatchSize: 100, Now: func() time.Time { return h.now }, Token: func() (string, error) { return strings.Repeat("a", 32), nil },
	})
	if err != nil {
		t.Fatal("unable to construct blocking reconciler")
	}
	firstDone := make(chan error, 1)
	go func() {
		_, runErr := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)})
		firstDone <- runErr
	}()
	select {
	case <-blocking.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first run did not reach blocking client")
	}
	if _, err := reconciler.Run(context.Background(), RunOptions{FeedOrder: feedOrder(h)}); err == nil || !IsCategory(err, ErrBusy) {
		t.Fatal("overlapping run did not fail fast")
	}
	close(blocking.release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal("first run failed after release")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first run did not finish")
	}
}
