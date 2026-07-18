package lapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"crowdshield/internal/credentials"
	"crowdshield/internal/network"
)

const (
	maxTokenBytes = 16 << 10
	maxBatchSize  = 500
)

var (
	clientFeedName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	operationToken = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

type Options struct {
	Credentials       *credentials.Credentials
	UserAgent         string
	RequestTimeout    time.Duration
	ConnectTimeout    time.Duration
	MaxResponseBytes  int64
	AuthRefreshBefore time.Duration
	HTTPClient        *http.Client
	Now               func() time.Time
}

type Client struct {
	credentials       *credentials.Credentials
	base              *url.URL
	userAgent         string
	requestTimeout    time.Duration
	maxResponseBytes  int64
	authRefreshBefore time.Duration
	httpClient        *http.Client
	now               func() time.Time

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

func (c *Client) String() string   { return "CrowdSec LAPI client [REDACTED]" }
func (c *Client) GoString() string { return "lapi.Client{[REDACTED]}" }

func validUserAgent(value string) bool {
	if len(value) < 3 || len(value) > 128 || strings.Count(value, "/") != 1 {
		return false
	}
	parts := strings.Split(value, "/")
	return parts[0] != "" && parts[1] != "" && strings.IndexFunc(value, unicode.IsControl) < 0 && !strings.ContainsAny(value, " \t")
}

func New(options Options) (*Client, error) {
	if options.Credentials == nil || options.Credentials.Login() == "" || options.Credentials.Password() == "" ||
		!validUserAgent(options.UserAgent) || options.RequestTimeout <= 0 || options.RequestTimeout > 2*time.Minute ||
		options.ConnectTimeout <= 0 || options.ConnectTimeout > time.Minute || options.MaxResponseBytes < 1024 || options.MaxResponseBytes > 64<<20 ||
		options.AuthRefreshBefore < 0 || options.AuthRefreshBefore >= time.Hour {
		return nil, lapiError(ErrContract, nil)
	}
	endpoint := options.Credentials.Endpoint()
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, lapiError(ErrContract, nil)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.HTTPClient == nil {
		dialer := &net.Dialer{Timeout: options.ConnectTimeout, KeepAlive: 30 * time.Second}
		transport := &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			MaxIdleConnsPerHost:   2,
			MaxConnsPerHost:       2,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   options.ConnectTimeout,
			ResponseHeaderTimeout: options.RequestTimeout,
			ExpectContinueTimeout: time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		}
		options.HTTPClient = &http.Client{Transport: transport}
	}
	return &Client{
		credentials: options.Credentials, base: endpoint, userAgent: options.UserAgent,
		requestTimeout: options.RequestTimeout, maxResponseBytes: options.MaxResponseBytes,
		authRefreshBefore: options.AuthRefreshBefore, httpClient: options.HTTPClient, now: options.Now,
	}, nil
}

func (c *Client) CloseIdleConnections() {
	if c != nil && c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

func (c *Client) endpoint(route string, query url.Values) string {
	endpoint := *c.base
	basePath := strings.TrimRight(endpoint.Path, "/")
	if !strings.HasSuffix(basePath, "/v1") {
		basePath += "/v1"
	}
	endpoint.Path = basePath + route
	endpoint.RawPath = ""
	endpoint.RawQuery = query.Encode()
	endpoint.Fragment = ""
	return endpoint.String()
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func containsStatus(status int, allowed []int) bool {
	for _, candidate := range allowed {
		if status == candidate {
			return true
		}
	}
	return false
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func (c *Client) perform(ctx context.Context, method, route string, query url.Values, payload any, bearer string, expected ...int) ([]byte, error) {
	if c == nil || c.httpClient == nil {
		return nil, lapiError(ErrContract, nil)
	}
	var encoded []byte
	var err error
	if payload != nil {
		encoded, err = json.Marshal(payload)
		if err != nil {
			return nil, lapiError(ErrContract, err)
		}
		defer zeroBytes(encoded)
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, c.endpoint(route, query), bytes.NewReader(encoded))
	if err != nil {
		return nil, lapiError(ErrRequest, err)
	}
	request.Header.Set("User-Agent", c.userAgent)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, lapiError(ErrRequest, err)
	}
	if response == nil || response.Body == nil {
		return nil, lapiError(ErrContract, nil)
	}
	defer response.Body.Close()
	if response.ContentLength > c.maxResponseBytes {
		return nil, lapiError(ErrResponseSize, nil)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, lapiError(ErrRequest, err)
	}
	if int64(len(body)) > c.maxResponseBytes {
		zeroBytes(body)
		return nil, lapiError(ErrResponseSize, nil)
	}
	if !containsStatus(response.StatusCode, expected) {
		zeroBytes(body)
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, lapiStatusError(ErrAuth, response.StatusCode, nil)
		case http.StatusNotFound:
			return nil, lapiStatusError(ErrNotFound, response.StatusCode, nil)
		default:
			return nil, lapiStatusError(ErrStatus, response.StatusCode, nil)
		}
	}
	if len(body) > 0 && !isJSONContentType(response.Header.Get("Content-Type")) {
		zeroBytes(body)
		return nil, lapiError(ErrContentType, nil)
	}
	return body, nil
}

func decodeJSON(body []byte, target any) error {
	defer zeroBytes(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return lapiError(ErrDecode, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return lapiError(ErrDecode, err)
	}
	return nil
}

type loginRequest struct {
	MachineID string `json:"machine_id"`
	Password  string `json:"password"`
}

type loginResponse struct {
	Code   int    `json:"code"`
	Expire string `json:"expire"`
	Token  string `json:"token"`
}

func (c *Client) loginLocked(ctx context.Context) error {
	password := c.credentials.Password()
	responseBody, err := c.perform(ctx, http.MethodPost, "/watchers/login", nil,
		loginRequest{MachineID: c.credentials.Login(), Password: password}, "", http.StatusOK)
	password = ""
	if err != nil {
		return err
	}
	var response loginResponse
	if err := decodeJSON(responseBody, &response); err != nil {
		return err
	}
	expiry, err := time.Parse(time.RFC3339, response.Expire)
	if err != nil || response.Token == "" || len(response.Token) > maxTokenBytes || strings.IndexFunc(response.Token, unicode.IsControl) >= 0 ||
		!expiry.After(c.now().Add(c.authRefreshBefore)) || (response.Code != 0 && response.Code != http.StatusOK) {
		return lapiError(ErrContract, err)
	}
	c.token = response.Token
	c.tokenExpiry = expiry.UTC()
	return nil
}

func (c *Client) ensureToken(ctx context.Context, force bool) error {
	if c == nil {
		return lapiError(ErrContract, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && c.now().Add(c.authRefreshBefore).Before(c.tokenExpiry) {
		return nil
	}
	c.token = ""
	c.tokenExpiry = time.Time{}
	return c.loginLocked(ctx)
}

// Authenticate verifies watcher credentials at startup while reusing a valid
// cached token. Returned errors carry only the bounded LAPI category.
func (c *Client) Authenticate(ctx context.Context) error {
	if ctx == nil {
		return lapiError(ErrContract, nil)
	}
	return c.ensureToken(ctx, false)
}

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Client) refreshRejectedToken(ctx context.Context, rejected string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.token != rejected && c.now().Add(c.authRefreshBefore).Before(c.tokenExpiry) {
		return nil
	}
	c.token = ""
	c.tokenExpiry = time.Time{}
	return c.loginLocked(ctx)
}

func isUnauthorized(err error) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == ErrAuth && target.status == http.StatusUnauthorized
}

func (c *Client) authenticated(ctx context.Context, method, route string, query url.Values, payload any, expected ...int) ([]byte, error) {
	if err := c.ensureToken(ctx, false); err != nil {
		return nil, err
	}
	token := c.currentToken()
	body, err := c.perform(ctx, method, route, query, payload, token, expected...)
	if !isUnauthorized(err) {
		return body, err
	}
	if err := c.refreshRejectedToken(ctx, token); err != nil {
		return nil, err
	}
	return c.perform(ctx, method, route, query, payload, c.currentToken(), expected...)
}

func canonicalDecision(input DecisionInput) (DecisionInput, error) {
	if strings.TrimSpace(input.Value) != input.Value {
		return DecisionInput{}, lapiError(ErrContract, nil)
	}
	switch input.Scope {
	case "Ip":
		if strings.Contains(input.Value, "/") {
			return DecisionInput{}, lapiError(ErrContract, nil)
		}
		address, err := network.NormalizeAddress(input.Value)
		if err != nil {
			return DecisionInput{}, lapiError(ErrContract, err)
		}
		prefix := netip.PrefixFrom(address, address.BitLen())
		if safe, _ := network.IsSafePrefix(prefix); !safe {
			return DecisionInput{}, lapiError(ErrContract, nil)
		}
		return DecisionInput{Scope: "Ip", Value: address.String()}, nil
	case "Range":
		if !strings.Contains(input.Value, "/") {
			return DecisionInput{}, lapiError(ErrContract, nil)
		}
		prefix, err := network.NormalizePrefix(input.Value)
		if err != nil || network.ValidateKind(prefix, network.KindRange) != nil {
			return DecisionInput{}, lapiError(ErrContract, err)
		}
		if safe, _ := network.IsSafePrefix(prefix); !safe {
			return DecisionInput{}, lapiError(ErrContract, nil)
		}
		return DecisionInput{Scope: "Range", Value: prefix.String()}, nil
	default:
		return DecisionInput{}, lapiError(ErrContract, nil)
	}
}

func buildWireAlert(request CreateRequest, now time.Time) (wireAlert, error) {
	if !clientFeedName.MatchString(request.FeedName) || len(request.FeedName) > 64 || !operationToken.MatchString(request.OperationToken) ||
		request.Duration < time.Minute || request.Duration > 7*24*time.Hour || len(request.Decisions) < 1 || len(request.Decisions) > maxBatchSize {
		return wireAlert{}, lapiError(ErrContract, nil)
	}
	scenario := "crowdshield/" + request.FeedName
	decisions := make([]Decision, 0, len(request.Decisions))
	seen := make(map[string]struct{}, len(request.Decisions))
	for _, input := range request.Decisions {
		canonical, err := canonicalDecision(input)
		if err != nil {
			return wireAlert{}, err
		}
		key := canonical.Scope + "\x00" + canonical.Value
		if _, exists := seen[key]; exists {
			return wireAlert{}, lapiError(ErrContract, nil)
		}
		seen[key] = struct{}{}
		decisions = append(decisions, Decision{
			Origin: "crowdshield", Type: "ban", Scope: canonical.Scope, Value: canonical.Value,
			Duration: request.Duration.String(), Scenario: scenario,
		})
	}
	timestamp := now.UTC().Format(time.RFC3339Nano)
	meta := []wireMetaItem{{Key: "service", Value: "crowdshield"}}
	return wireAlert{
		Scenario: scenario, ScenarioHash: "crowdshield:" + request.OperationToken, ScenarioVersion: "1.0",
		Message: "External threat feed: " + request.FeedName, EventsCount: 1,
		StartAt: timestamp, StopAt: timestamp, Capacity: len(decisions), Leakspeed: "0", Simulated: false,
		Events: []wireEvent{{Timestamp: timestamp, Meta: meta}}, Remediation: true, Decisions: decisions,
		Source: wireSource{Scope: "service", Value: "crowdshield"}, Meta: meta,
		Labels: []string{"crowdshield", "operation:" + request.OperationToken}, Kind: "crowdshield",
	}, nil
}

func (c *Client) CreateAlert(ctx context.Context, request CreateRequest) (int64, error) {
	alert, err := buildWireAlert(request, c.now())
	if err != nil {
		return 0, err
	}
	body, err := c.authenticated(ctx, http.MethodPost, "/alerts", nil, []wireAlert{alert}, http.StatusCreated)
	if err != nil {
		return 0, err
	}
	var response []string
	if err := decodeJSON(body, &response); err != nil {
		return 0, err
	}
	if len(response) != 1 {
		return 0, lapiError(ErrContract, nil)
	}
	alertID, err := strconv.ParseInt(response[0], 10, 64)
	if err != nil || alertID <= 0 {
		return 0, lapiError(ErrContract, err)
	}
	return alertID, nil
}

func (c *Client) GetAlert(ctx context.Context, alertID int64) (Alert, error) {
	if alertID <= 0 {
		return Alert{}, lapiError(ErrContract, nil)
	}
	body, err := c.authenticated(ctx, http.MethodGet, "/alerts/"+strconv.FormatInt(alertID, 10), nil, nil, http.StatusOK)
	if err != nil {
		return Alert{}, err
	}
	var alert Alert
	if err := decodeJSON(body, &alert); err != nil {
		return Alert{}, err
	}
	if alert.ID != alertID {
		return Alert{}, lapiError(ErrContract, nil)
	}
	return alert, nil
}

func (c *Client) ExpireDecision(ctx context.Context, decisionID int64) error {
	if decisionID <= 0 {
		return lapiError(ErrContract, nil)
	}
	body, err := c.authenticated(ctx, http.MethodDelete, "/decisions/"+strconv.FormatInt(decisionID, 10), nil, nil, http.StatusOK, http.StatusNoContent)
	zeroBytes(body)
	return err
}

func (c *Client) FindOperation(ctx context.Context, feedName, token string) (Alert, bool, error) {
	if !clientFeedName.MatchString(feedName) || !operationToken.MatchString(token) {
		return Alert{}, false, lapiError(ErrContract, nil)
	}
	query := url.Values{}
	query.Set("scenario", "crowdshield/"+feedName)
	query.Set("since", "24h")
	query.Set("limit", "100")
	body, err := c.authenticated(ctx, http.MethodGet, "/alerts", query, nil, http.StatusOK)
	if err != nil {
		return Alert{}, false, err
	}
	var alerts []Alert
	if err := decodeJSON(body, &alerts); err != nil {
		return Alert{}, false, err
	}
	if len(alerts) > 100 {
		return Alert{}, false, lapiError(ErrContract, nil)
	}
	targetHash := "crowdshield:" + token
	var found *Alert
	for index := range alerts {
		if alerts[index].Scenario == "crowdshield/"+feedName && alerts[index].ScenarioHash == targetHash {
			if found != nil {
				return Alert{}, false, lapiError(ErrContract, nil)
			}
			candidate := alerts[index]
			found = &candidate
		}
	}
	if found == nil {
		return Alert{}, false, nil
	}
	return *found, true, nil
}
