package feed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func response(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func testFetcher(do roundTripFunc) *Fetcher {
	return &Fetcher{client: &http.Client{Transport: do}, userAgent: "crowdshield/test"}
}

func validFetchRequest() FetchRequest {
	return FetchRequest{
		URL:          "https://feed.example.invalid/list",
		Timeout:      time.Second,
		MaxBytes:     1024,
		ContentTypes: []string{"text/plain"},
	}
}

func TestFetchUsesConditionalHeadersAndBoundedIdentity(t *testing.T) {
	const body = "8.8.8.0/24\n"
	fetcher := testFetcher(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.Header.Get("User-Agent") != "crowdshield/test" {
			t.Fatal("request identity or method changed")
		}
		if request.Header.Get("If-None-Match") != `"fixture-etag"` || request.Header.Get("If-Modified-Since") == "" {
			t.Fatal("conditional request headers missing")
		}
		result := response(http.StatusOK, "text/plain; charset=utf-8", body)
		result.Header.Set("ETag", `"next-etag"`)
		result.Header.Set("Last-Modified", "Wed, 15 Jul 2026 12:00:00 GMT")
		return result, nil
	})
	request := validFetchRequest()
	request.ETag = `"fixture-etag"`
	request.LastModified = "Tue, 14 Jul 2026 12:00:00 GMT"
	result, err := fetcher.Fetch(context.Background(), request)
	if err != nil {
		t.Fatal("valid feed response rejected")
	}
	defer result.Destroy()
	if string(result.Body) != body || result.ContentHash == "" || result.ETag != `"next-etag"` || result.LastModified == "" || result.NotModified {
		t.Fatal("feed response metadata or body missing")
	}
}

func TestFetchHandlesNotModified(t *testing.T) {
	fetcher := testFetcher(func(*http.Request) (*http.Response, error) {
		result := response(http.StatusNotModified, "", "")
		result.Header.Set("ETag", `"same"`)
		return result, nil
	})
	result, err := fetcher.Fetch(context.Background(), validFetchRequest())
	if err != nil || !result.NotModified || len(result.Body) != 0 {
		t.Fatal("304 response not handled")
	}
}

func TestFetchEnforcesDeclaredAndStreamedBodyLimits(t *testing.T) {
	for _, declared := range []bool{true, false} {
		t.Run(map[bool]string{true: "declared", false: "streamed"}[declared], func(t *testing.T) {
			fetcher := testFetcher(func(*http.Request) (*http.Response, error) {
				result := response(http.StatusOK, "text/plain", strings.Repeat("x", 65))
				if !declared {
					result.ContentLength = -1
				}
				return result, nil
			})
			request := validFetchRequest()
			request.MaxBytes = 64
			_, err := fetcher.Fetch(context.Background(), request)
			if err == nil || !IsCategory(err, ErrBodySize) {
				t.Fatal("oversized response accepted")
			}
		})
	}
}

func TestFetchRejectsContentTypeAndHTML(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		category    ErrorCategory
	}{
		{name: "wrong media type", contentType: "application/json", body: "{}\n", category: ErrContentType},
		{name: "HTML body", contentType: "text/plain", body: "  <!DOCTYPE html><html></html>\n", category: ErrHTML},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fetcher := testFetcher(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, tc.contentType, tc.body), nil
			})
			_, err := fetcher.Fetch(context.Background(), validFetchRequest())
			if err == nil || !IsCategory(err, tc.category) {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}

func TestFetchClassifiesStatusAndRetryAfter(t *testing.T) {
	fetcher := testFetcher(func(*http.Request) (*http.Response, error) {
		result := response(http.StatusTooManyRequests, "text/plain", "ignored")
		result.Header.Set("Retry-After", "120")
		return result, nil
	})
	_, err := fetcher.Fetch(context.Background(), validFetchRequest())
	if err == nil || !IsCategory(err, ErrHTTPStatus) || RetryAfter(err) != 2*time.Minute {
		t.Fatal("retryable status was not classified")
	}
}

func TestFetchErrorDoesNotEchoRawTransportError(t *testing.T) {
	const canary = "https://user:credential-canary@feed.example.invalid/private"
	fetcher := testFetcher(func(*http.Request) (*http.Response, error) {
		return nil, errors.New(canary)
	})
	_, err := fetcher.Fetch(context.Background(), validFetchRequest())
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatal("transport error disclosed raw details")
	}
}

func TestProductionFetcherRejectsLoopbackDial(t *testing.T) {
	fetcher, err := NewFetcher(FetcherOptions{
		UserAgent:             "crowdshield/test",
		MaxRedirects:          1,
		AllowHTTP:             true,
		ConnectTimeout:        100 * time.Millisecond,
		DNSLookupTimeout:      100 * time.Millisecond,
		TLSHandshakeTimeout:   100 * time.Millisecond,
		ResponseHeaderTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal("unable to construct production fetcher")
	}
	defer fetcher.CloseIdleConnections()
	request := validFetchRequest()
	request.URL = "http://127.0.0.1:1/list"
	_, err = fetcher.Fetch(context.Background(), request)
	if err == nil || !IsCategory(err, ErrSSRF) {
		t.Fatal("loopback target was not rejected")
	}
}

func TestRedirectPolicyRejectsDowngradeAndExcess(t *testing.T) {
	policy := redirectPolicy(1, true)
	original, _ := http.NewRequest(http.MethodGet, "https://feed.example.invalid/list", nil)
	downgrade, _ := http.NewRequest(http.MethodGet, "http://feed.example.invalid/list", nil)
	if err := policy(downgrade, []*http.Request{original}); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
	next, _ := http.NewRequest(http.MethodGet, "https://other.example.invalid/list", nil)
	if err := policy(next, []*http.Request{original, next}); err == nil {
		t.Fatal("redirect limit not enforced")
	}
}

func TestFetchResultDestroyClearsBody(t *testing.T) {
	result := FetchResult{Body: []byte("sensitive-feed-body")}
	result.Destroy()
	if result.Body != nil {
		t.Fatal("fetch body not released")
	}
}
