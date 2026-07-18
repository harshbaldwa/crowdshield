package reconcile

import "errors"

type ErrorCategory string

const (
	ErrBusy      ErrorCategory = "busy"
	ErrContract  ErrorCategory = "contract"
	ErrState     ErrorCategory = "state"
	ErrLAPI      ErrorCategory = "lapi"
	ErrOwnership ErrorCategory = "ownership"
	ErrToken     ErrorCategory = "token"
)

type Error struct {
	Category ErrorCategory
	cause    error
}

func (e *Error) Error() string {
	if e == nil {
		return "reconcile error"
	}
	return "reconcile: " + string(e.Category)
}

func (e *Error) Unwrap() error { return e.cause }

func reconcileError(category ErrorCategory, cause error) error {
	return &Error{Category: category, cause: cause}
}

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}
