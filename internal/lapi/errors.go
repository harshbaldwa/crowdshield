package lapi

import "errors"

type ErrorCategory string

const (
	ErrAuth         ErrorCategory = "auth"
	ErrRequest      ErrorCategory = "request"
	ErrStatus       ErrorCategory = "status"
	ErrResponseSize ErrorCategory = "response_size"
	ErrContentType  ErrorCategory = "content_type"
	ErrDecode       ErrorCategory = "decode"
	ErrContract     ErrorCategory = "contract"
	ErrNotFound     ErrorCategory = "not_found"
)

type Error struct {
	Category ErrorCategory
	cause    error
	status   int
}

func (e *Error) Error() string {
	if e == nil {
		return "lapi error"
	}
	return "lapi: " + string(e.Category)
}

func (e *Error) Unwrap() error { return e.cause }

func lapiError(category ErrorCategory, cause error) error {
	return &Error{Category: category, cause: cause}
}

func lapiStatusError(category ErrorCategory, status int, cause error) error {
	return &Error{Category: category, cause: cause, status: status}
}

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}
