// Package logsafe is the only application logging boundary. Its API accepts
// closed enums and counts rather than arbitrary messages, errors, or values.
package logsafe

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type Operation string

const (
	OpRun          Operation = "run"
	OpFeedSync     Operation = "feed_sync"
	OpFeedDownload Operation = "feed_download"
	OpFeedValidate Operation = "feed_validate"
	OpLAPIAuth     Operation = "lapi_auth"
	OpLAPIRequest  Operation = "lapi_request"
	OpDatabase     Operation = "database"
	OpNotification Operation = "notification"
	OpHTTPServer   Operation = "http_server"
	OpPrune        Operation = "prune"
)

type ErrorCategory string

const (
	CategoryConfig         ErrorCategory = "config"
	CategoryCredential     ErrorCategory = "credential"
	CategoryFeedDownload   ErrorCategory = "feed_download"
	CategoryFeedValidation ErrorCategory = "feed_validation"
	CategoryLAPIAuth       ErrorCategory = "lapi_auth"
	CategoryLAPIRequest    ErrorCategory = "lapi_request"
	CategoryDatabase       ErrorCategory = "database"
	CategoryNotification   ErrorCategory = "notification"
	CategoryOwnership      ErrorCategory = "ownership"
	CategoryPanic          ErrorCategory = "panic_recovered"
	CategoryHTTPInternal   ErrorCategory = "http_internal"
	CategoryInternal       ErrorCategory = "internal"
)

type Transaction string

const (
	TxCommitted  Transaction = "committed"
	TxRolledBack Transaction = "rolled_back"
)

var (
	ErrInvalidEvent = errors.New("invalid structured log event")
	feedPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
)

type Event struct {
	Level         Level
	Operation     Operation
	Feed          string
	Duration      time.Duration
	Total         int
	Added         int
	Refreshed     int
	Removed       int
	Rejected      int
	Skipped       int
	LAPIRequests  int
	Success       bool
	ErrorCategory ErrorCategory
	Transaction   Transaction
}

type Logger struct {
	logger *slog.Logger
}

func New(writer io.Writer, level string) (*Logger, error) {
	var minimum slog.Level
	switch strings.ToLower(level) {
	case "debug":
		minimum = slog.LevelDebug
	case "info":
		minimum = slog.LevelInfo
	case "warn", "warning":
		minimum = slog.LevelWarn
	case "error":
		minimum = slog.LevelError
	default:
		return nil, ErrInvalidEvent
	}
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: minimum, AddSource: false})
	return &Logger{logger: slog.New(handler)}, nil
}

func validOperation(value Operation) bool {
	switch value {
	case OpRun, OpFeedSync, OpFeedDownload, OpFeedValidate, OpLAPIAuth, OpLAPIRequest, OpDatabase, OpNotification, OpHTTPServer, OpPrune:
		return true
	default:
		return false
	}
}

func validCategory(value ErrorCategory) bool {
	switch value {
	case CategoryConfig, CategoryCredential, CategoryFeedDownload, CategoryFeedValidation, CategoryLAPIAuth, CategoryLAPIRequest, CategoryDatabase, CategoryNotification, CategoryOwnership, CategoryPanic, CategoryHTTPInternal, CategoryInternal:
		return true
	default:
		return false
	}
}

func validLevel(value Level) bool {
	return value == LevelDebug || value == LevelInfo || value == LevelWarn || value == LevelError
}

func (e Event) validate() error {
	if !validLevel(e.Level) || !validOperation(e.Operation) {
		return ErrInvalidEvent
	}
	if e.Feed != "" && (len(e.Feed) > 64 || !feedPattern.MatchString(e.Feed)) {
		return ErrInvalidEvent
	}
	if e.Duration < 0 || e.Total < 0 || e.Added < 0 || e.Refreshed < 0 || e.Removed < 0 || e.Rejected < 0 || e.Skipped < 0 || e.LAPIRequests < 0 {
		return ErrInvalidEvent
	}
	if e.Success && e.ErrorCategory != "" {
		return ErrInvalidEvent
	}
	if !e.Success && !validCategory(e.ErrorCategory) {
		return ErrInvalidEvent
	}
	if e.Transaction != "" && e.Transaction != TxCommitted && e.Transaction != TxRolledBack {
		return ErrInvalidEvent
	}
	return nil
}

func (l *Logger) Log(ctx context.Context, event Event) error {
	if l == nil || l.logger == nil || event.validate() != nil {
		return ErrInvalidEvent
	}
	attrs := []slog.Attr{
		slog.String("operation", string(event.Operation)),
		slog.Int64("duration_ms", event.Duration.Milliseconds()),
		slog.Int("total", event.Total),
		slog.Int("added", event.Added),
		slog.Int("refreshed", event.Refreshed),
		slog.Int("removed", event.Removed),
		slog.Int("rejected", event.Rejected),
		slog.Int("skipped", event.Skipped),
		slog.Int("lapi_requests", event.LAPIRequests),
		slog.Bool("success", event.Success),
	}
	if event.Feed != "" {
		attrs = append(attrs, slog.String("feed", event.Feed))
	}
	if event.ErrorCategory != "" {
		attrs = append(attrs, slog.String("error_category", string(event.ErrorCategory)))
	}
	if event.Transaction != "" {
		attrs = append(attrs, slog.String("transaction", string(event.Transaction)))
	}
	l.logger.LogAttrs(ctx, event.Level, "crowdshield_event", attrs...)
	return nil
}

// Failure intentionally discards rawError. It exists so callers can preserve
// control-flow errors while proving that only the bounded category is logged.
func (l *Logger) Failure(ctx context.Context, operation Operation, feed string, category ErrorCategory, rawError error) error {
	_ = rawError
	return l.Log(ctx, Event{Level: LevelError, Operation: operation, Feed: feed, Success: false, ErrorCategory: category})
}

// Guard executes fn and converts a panic into one sanitized event. It does not
// include the panic value or stack trace.
func (l *Logger) Guard(ctx context.Context, operation Operation, fn func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
			_ = l.Log(ctx, Event{Level: LevelError, Operation: operation, Success: false, ErrorCategory: CategoryPanic})
		}
	}()
	fn()
	return false
}

type httpErrorWriter struct {
	ctx    context.Context
	logger *Logger
}

func (w httpErrorWriter) Write(body []byte) (int, error) {
	_ = w.logger.Log(w.ctx, Event{Level: LevelError, Operation: OpHTTPServer, Success: false, ErrorCategory: CategoryHTTPInternal})
	return len(body), nil
}

// HTTPErrorWriter adapts net/http's internal logger while discarding its raw text.
func (l *Logger) HTTPErrorWriter(ctx context.Context) io.Writer {
	if ctx == nil {
		ctx = context.Background()
	}
	return httpErrorWriter{ctx: ctx, logger: l}
}
