package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"crowdshield/internal/config"
)

var (
	ErrInvalidTransport = errors.New("invalid notification transport")
	ErrTransport        = errors.New("notification transport failure")
	ErrResponse         = errors.New("notification response failure")
	topicPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

const maxResponseBytes = int64(4 << 10)

type Transport interface {
	Send(context.Context, Notice) error
}

type HTTPOptions struct {
	ServerURL string
	Topic     string
	Token     config.Secret
	Timeout   time.Duration
	AllowHTTP bool
}

type HTTPTransport struct {
	endpoint *url.URL
	token    config.Secret
	client   *http.Client
}

func validToken(token config.Secret) bool {
	if !token.IsSet() {
		return true
	}
	value := token.Reveal()
	return len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00")
}

func NewHTTPTransport(options HTTPOptions) (*HTTPTransport, error) {
	if len(options.ServerURL) == 0 || len(options.ServerURL) > 2048 ||
		!topicPattern.MatchString(options.Topic) || options.Timeout <= 0 ||
		options.Timeout > 2*time.Minute || !validToken(options.Token) {
		return nil, ErrInvalidTransport
	}
	parsed, err := url.Parse(options.ServerURL)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(parsed.Host, "\r\n\x00") {
		return nil, ErrInvalidTransport
	}
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !options.AllowHTTP) {
		return nil, ErrInvalidTransport
	}
	endpoint := parsed.JoinPath(options.Topic)
	client := &http.Client{
		Timeout: options.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 || len(via) == 0 ||
				request.URL.Scheme != via[0].URL.Scheme || request.URL.Host != via[0].URL.Host {
				return ErrTransport
			}
			return nil
		},
	}
	return &HTTPTransport{endpoint: endpoint, token: options.Token, client: client}, nil
}

func (t *HTTPTransport) CloseIdleConnections() {
	if t != nil && t.client != nil {
		t.client.CloseIdleConnections()
	}
}

func (t *HTTPTransport) Send(ctx context.Context, notice Notice) error {
	if t == nil || t.endpoint == nil || t.client == nil || ctx == nil {
		return ErrTransport
	}
	rendered, err := renderNotice(notice)
	if err != nil {
		return ErrInvalidNotice
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint.String(), strings.NewReader(rendered.body))
	if err != nil {
		return ErrTransport
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	request.Header.Set("Title", rendered.title)
	request.Header.Set("Priority", rendered.priority)
	request.Header.Set("Tags", rendered.tags)
	if t.token.IsSet() {
		request.Header.Set("Authorization", "Bearer "+t.token.Reveal())
	}
	response, err := t.client.Do(request)
	if err != nil {
		return ErrTransport
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ErrResponse
	}
	return nil
}
