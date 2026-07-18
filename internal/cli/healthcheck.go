package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHealthcheckURL     = "http://127.0.0.1:9090/healthz"
	defaultHealthcheckTimeout = 2 * time.Second
	maxHealthcheckTimeout     = 10 * time.Second
	maxHealthcheckBodyBytes   = int64(128)
)

var (
	errInvalidHealthcheck = errors.New("invalid healthcheck options")
	errHealthcheckFailed  = errors.New("healthcheck failed")
)

type healthcheckResponse struct {
	Status string `json:"status"`
}

func healthcheckTarget(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "/healthz" || parsed.RawPath != "" || strings.ContainsAny(parsed.Host, "\r\n\x00") {
		return nil, errInvalidHealthcheck
	}
	host := parsed.Hostname()
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return nil, errInvalidHealthcheck
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errInvalidHealthcheck
	}
	return parsed, nil
}

func decodeHealthcheck(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var response healthcheckResponse
	if err := decoder.Decode(&response); err != nil || response.Status != "alive" {
		return errHealthcheckFailed
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errHealthcheckFailed
	}
	return nil
}

func runHealthcheck(ctx context.Context, rawURL string, timeout time.Duration) error {
	if ctx == nil || timeout <= 0 || timeout > maxHealthcheckTimeout {
		return errInvalidHealthcheck
	}
	target, err := healthcheckTarget(rawURL)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, target.String(), nil)
	if err != nil {
		return errHealthcheckFailed
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return errHealthcheckFailed
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxHealthcheckBodyBytes {
		return errHealthcheckFailed
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errHealthcheckFailed
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHealthcheckBodyBytes+1))
	if err != nil || int64(len(body)) > maxHealthcheckBodyBytes {
		return errHealthcheckFailed
	}
	return decodeHealthcheck(body)
}

func healthcheckCommand(ctx context.Context, args []string, _ io.Writer, stderr io.Writer) int {
	flags := commandFlags("healthcheck")
	target := flags.String("url", defaultHealthcheckURL, "loopback liveness URL")
	timeout := flags.Duration("timeout", defaultHealthcheckTimeout, "request timeout")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		writeUsage(stderr)
		return ExitUsage
	}
	err := runHealthcheck(ctx, *target, *timeout)
	if errors.Is(err, errInvalidHealthcheck) {
		writeUsage(stderr)
		return ExitUsage
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "healthcheck failed")
		return ExitOperational
	}
	return ExitSuccess
}
