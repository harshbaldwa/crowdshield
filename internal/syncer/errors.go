package syncer

import "errors"

type ErrorCategory string

const (
	ErrConfig    ErrorCategory = "config"
	ErrState     ErrorCategory = "state"
	ErrFeed      ErrorCategory = "feed"
	ErrReconcile ErrorCategory = "reconcile"
	ErrSelection ErrorCategory = "selection"
	ErrDegraded  ErrorCategory = "degraded"
)

type Error struct {
	Category ErrorCategory
	cause    error
}

func (e *Error) Error() string {
	if e == nil {
		return "sync error"
	}
	return "sync: " + string(e.Category)
}

func (e *Error) Unwrap() error { return e.cause }

func syncError(category ErrorCategory, cause error) error {
	return &Error{Category: category, cause: cause}
}

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}
