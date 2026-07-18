package state

import "errors"

type ErrorCategory string

const (
	ErrOpen        ErrorCategory = "open"
	ErrMigration   ErrorCategory = "migration"
	ErrIntegrity   ErrorCategory = "integrity"
	ErrQuery       ErrorCategory = "query"
	ErrTransaction ErrorCategory = "transaction"
	ErrNotFound    ErrorCategory = "not_found"
	ErrConstraint  ErrorCategory = "constraint"
)

type Error struct {
	Category ErrorCategory
	cause    error
}

func (e *Error) Error() string {
	if e == nil {
		return "state error"
	}
	return "state: " + string(e.Category)
}

func (e *Error) Unwrap() error { return e.cause }

func stateError(category ErrorCategory, cause error) error {
	return &Error{Category: category, cause: cause}
}

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}
