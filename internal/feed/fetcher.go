package feed

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"crowdshield/internal/network"
)

var (
	errSSRFBlocked = errors.New("feed target blocked")
	errRedirect    = errors.New("feed redirect blocked")
)

type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type FetcherOptions struct {
	UserAgent             string
	MaxRedirects          int
	AllowHTTP             bool
	ConnectTimeout        time.Duration
	DNSLookupTimeout      time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	Resolver              resolver
}

type FetchRequest struct {
	URL          string
	Timeout      time.Duration
	MaxBytes     int64
	ContentTypes []string
	ETag         string
	LastModified string
}

type FetchResult struct {
	Body         []byte
	NotModified  bool
	ETag         string
	LastModified string
	ContentHash  string
}

func (r *FetchResult) Destroy() {
	if r == nil {
		return
	}
	for i := range r.Body {
		r.Body[i] = 0
	}
	r.Body = nil
}

type Fetcher struct {
	client    *http.Client
	userAgent string
	transport *http.Transport
	allowHTTP bool
}

func hasHeaderControl(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\t' }) >= 0
}

func validUserAgent(value string) bool {
	return value != "" && len(value) <= 128 && strings.Count(value, "/") == 1 && !hasHeaderControl(value)
}

func validateFetchURL(raw string, allowHTTP bool) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || hasHeaderControl(parsed.Host) {
		return nil, feedError(ErrRequest, err)
	}
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !allowHTTP) {
		return nil, feedError(ErrRequest, nil)
	}
	if literal, err := netip.ParseAddr(parsed.Hostname()); err == nil {
		literal = literal.Unmap()
		prefix := netip.PrefixFrom(literal, literal.BitLen())
		if safe, _ := network.IsSafePrefix(prefix); !safe {
			return nil, errSSRFBlocked
		}
	}
	return parsed, nil
}

func redirectPolicy(maxRedirects int, allowHTTP bool) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return errRedirect
		}
		parsed, err := validateFetchURL(request.URL.String(), allowHTTP)
		if err != nil {
			return errRedirect
		}
		if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && parsed.Scheme != "https" {
			return errRedirect
		}
		return nil
	}
}

type secureDialer struct {
	resolver   resolver
	dnsTimeout time.Duration
	dialer     net.Dialer
}

func safeAddress(address netip.Addr) bool {
	address = address.Unmap()
	prefix := netip.PrefixFrom(address, address.BitLen())
	safe, _ := network.IsSafePrefix(prefix)
	return safe
}

func (d secureDialer) DialContext(ctx context.Context, networkName, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errSSRFBlocked
	}
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal.Unmap()}
	} else {
		lookupCtx, cancel := context.WithTimeout(ctx, d.dnsTimeout)
		addresses, err = d.resolver.LookupNetIP(lookupCtx, "ip", host)
		cancel()
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		return nil, errSSRFBlocked
	}
	for _, resolved := range addresses {
		if !safeAddress(resolved) {
			return nil, errSSRFBlocked
		}
	}
	var lastError error
	for _, resolved := range addresses {
		connection, err := d.dialer.DialContext(ctx, networkName, net.JoinHostPort(resolved.String(), port))
		if err == nil {
			return connection, nil
		}
		lastError = err
	}
	return nil, lastError
}

func NewFetcher(options FetcherOptions) (*Fetcher, error) {
	if !validUserAgent(options.UserAgent) || options.MaxRedirects < 0 || options.MaxRedirects > 10 ||
		options.ConnectTimeout <= 0 || options.DNSLookupTimeout <= 0 || options.TLSHandshakeTimeout <= 0 || options.ResponseHeaderTimeout <= 0 {
		return nil, feedError(ErrPolicy, nil)
	}
	lookup := options.Resolver
	if lookup == nil {
		lookup = net.DefaultResolver
	}
	dialer := secureDialer{
		resolver:   lookup,
		dnsTimeout: options.DNSLookupTimeout,
		dialer: net.Dialer{
			Timeout:   options.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   options.TLSHandshakeTimeout,
		ResponseHeaderTimeout: options.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, CheckRedirect: redirectPolicy(options.MaxRedirects, options.AllowHTTP)}
	return &Fetcher{client: client, userAgent: options.UserAgent, transport: transport, allowHTTP: options.AllowHTTP}, nil
}

func (f *Fetcher) CloseIdleConnections() {
	if f != nil && f.transport != nil {
		f.transport.CloseIdleConnections()
	} else if f != nil && f.client != nil {
		f.client.CloseIdleConnections()
	}
}

func validConditional(value string, max int) bool {
	return len(value) <= max && !hasHeaderControl(value)
}

func allowedContentType(raw string, allowed []string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil || mediaType == "" || strings.EqualFold(mediaType, "text/html") {
		return false
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), mediaType) {
			return true
		}
	}
	return false
}

func responseValidators(header http.Header) (string, string, error) {
	etag := header.Get("ETag")
	if !validConditional(etag, 256) {
		return "", "", feedError(ErrResponseHeader, nil)
	}
	lastModified := header.Get("Last-Modified")
	if lastModified != "" {
		parsed, err := http.ParseTime(lastModified)
		if err != nil {
			return "", "", feedError(ErrResponseHeader, err)
		}
		lastModified = parsed.UTC().Format(http.TimeFormat)
	}
	return etag, lastModified, nil
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay > 0 && delay <= 24*time.Hour {
			return delay
		}
		return 0
	}
	if target, err := http.ParseTime(value); err == nil {
		delay := time.Until(target)
		if delay > 0 && delay <= 24*time.Hour {
			return delay
		}
	}
	return 0
}

func looksLikeHTML(body []byte) bool {
	limit := len(body)
	if limit > 512 {
		limit = 512
	}
	prefix := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(string(body[:limit]), "\ufeff")))
	return strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html") || strings.HasPrefix(prefix, "<head") || strings.HasPrefix(prefix, "<body")
}

func validateFetchRequest(request FetchRequest) error {
	if request.Timeout <= 0 || request.Timeout > 10*time.Minute || request.MaxBytes < 1 || request.MaxBytes > 64<<20 || len(request.ContentTypes) == 0 {
		return feedError(ErrPolicy, nil)
	}
	if !validConditional(request.ETag, 256) || !validConditional(request.LastModified, 128) {
		return feedError(ErrRequest, nil)
	}
	if request.LastModified != "" {
		if _, err := http.ParseTime(request.LastModified); err != nil {
			return feedError(ErrRequest, err)
		}
	}
	for _, contentType := range request.ContentTypes {
		if strings.TrimSpace(contentType) == "" || hasHeaderControl(contentType) {
			return feedError(ErrPolicy, nil)
		}
	}
	return nil
}

func (f *Fetcher) Fetch(ctx context.Context, request FetchRequest) (FetchResult, error) {
	if f == nil || f.client == nil || !validUserAgent(f.userAgent) {
		return FetchResult{}, feedError(ErrPolicy, nil)
	}
	if err := validateFetchRequest(request); err != nil {
		return FetchResult{}, err
	}
	parsed, err := validateFetchURL(request.URL, f.allowHTTP)
	if err != nil {
		if errors.Is(err, errSSRFBlocked) {
			return FetchResult{}, feedError(ErrSSRF, err)
		}
		return FetchResult{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return FetchResult{}, feedError(ErrRequest, err)
	}
	httpRequest.Header.Set("User-Agent", f.userAgent)
	httpRequest.Header.Set("Accept", strings.Join(request.ContentTypes, ", "))
	if request.ETag != "" {
		httpRequest.Header.Set("If-None-Match", request.ETag)
	}
	if request.LastModified != "" {
		httpRequest.Header.Set("If-Modified-Since", request.LastModified)
	}

	response, err := f.client.Do(httpRequest)
	if err != nil {
		switch {
		case errors.Is(err, errSSRFBlocked):
			return FetchResult{}, feedError(ErrSSRF, err)
		case errors.Is(err, errRedirect):
			return FetchResult{}, feedError(ErrRedirect, err)
		default:
			return FetchResult{}, feedError(ErrRequest, err)
		}
	}
	if response == nil || response.Body == nil {
		return FetchResult{}, feedError(ErrRequest, nil)
	}
	defer func() { _ = response.Body.Close() }()

	etag, lastModified, err := responseValidators(response.Header)
	if err != nil {
		return FetchResult{}, err
	}
	if response.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return FetchResult{NotModified: true, ETag: etag, LastModified: lastModified}, nil
	}
	if response.StatusCode != http.StatusOK {
		return FetchResult{}, statusError(parseRetryAfter(response.Header.Get("Retry-After")))
	}
	if response.ContentLength > request.MaxBytes {
		return FetchResult{}, feedError(ErrBodySize, nil)
	}
	if !allowedContentType(response.Header.Get("Content-Type"), request.ContentTypes) {
		return FetchResult{}, feedError(ErrContentType, nil)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, request.MaxBytes+1))
	if err != nil {
		return FetchResult{}, feedError(ErrRequest, err)
	}
	if int64(len(body)) > request.MaxBytes {
		for i := range body {
			body[i] = 0
		}
		return FetchResult{}, feedError(ErrBodySize, nil)
	}
	if looksLikeHTML(body) {
		for i := range body {
			body[i] = 0
		}
		return FetchResult{}, feedError(ErrHTML, nil)
	}
	hash := sha256.Sum256(body)
	return FetchResult{
		Body:         body,
		ETag:         etag,
		LastModified: lastModified,
		ContentHash:  hex.EncodeToString(hash[:]),
	}, nil
}
