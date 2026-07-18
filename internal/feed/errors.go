package feed

import (
	"errors"
	"time"
)

type ErrorCategory string

const (
	ErrFormat             ErrorCategory = "format"
	ErrPolicy             ErrorCategory = "policy"
	ErrEmpty              ErrorCategory = "empty"
	ErrLineTooLong        ErrorCategory = "line_too_long"
	ErrTruncated          ErrorCategory = "truncated"
	ErrMetadata           ErrorCategory = "metadata"
	ErrMalformedThreshold ErrorCategory = "malformed_threshold"
	ErrEntryCount         ErrorCategory = "entry_count"
	ErrSuspiciousChange   ErrorCategory = "suspicious_change"
	ErrRequest            ErrorCategory = "request"
	ErrSSRF               ErrorCategory = "ssrf"
	ErrRedirect           ErrorCategory = "redirect"
	ErrHTTPStatus         ErrorCategory = "http_status"
	ErrBodySize           ErrorCategory = "body_size"
	ErrContentType        ErrorCategory = "content_type"
	ErrHTML               ErrorCategory = "html"
	ErrResponseHeader     ErrorCategory = "response_header"
)

type Error struct {
	Category   ErrorCategory
	cause      error
	retryAfter time.Duration
}

func (e *Error) Error() string {
	if e == nil {
		return "feed error"
	}
	return "feed: " + string(e.Category)
}

func (e *Error) Unwrap() error { return e.cause }

func feedError(category ErrorCategory, cause error) error {
	return &Error{Category: category, cause: cause}
}

func statusError(retryAfter time.Duration) error {
	return &Error{Category: ErrHTTPStatus, retryAfter: retryAfter}
}

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}

// RetryAfter returns a bounded server-requested delay, if present.
func RetryAfter(err error) time.Duration {
	var target *Error
	if errors.As(err, &target) {
		return target.retryAfter
	}
	return 0
}
