package credentials

import "errors"

type ErrorCategory string

const (
	ErrMissing     ErrorCategory = "missing"
	ErrFileType    ErrorCategory = "file_type"
	ErrPermissions ErrorCategory = "permissions"
	ErrSize        ErrorCategory = "size"
	ErrYAML        ErrorCategory = "yaml"
	ErrFields      ErrorCategory = "fields"
	ErrURL         ErrorCategory = "url"
)

type Error struct {
	Category ErrorCategory
	cause    error
}

func (e *Error) Error() string {
	if e == nil {
		return "credential error"
	}
	return "CrowdSec credential: " + string(e.Category)
}

func (e *Error) Unwrap() error { return e.cause }

func credentialError(category ErrorCategory, cause error) error {
	return &Error{Category: category, cause: cause}
}

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}
