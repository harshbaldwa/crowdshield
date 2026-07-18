package config

import (
	"errors"
	"fmt"
)

// ErrorCategory is a bounded, non-sensitive configuration failure class.
type ErrorCategory string

const (
	ErrConfigSize    ErrorCategory = "config_size"
	ErrYAML          ErrorCategory = "yaml_invalid"
	ErrYAMLDocument  ErrorCategory = "yaml_multiple_documents"
	ErrEnvironment   ErrorCategory = "environment_invalid"
	ErrDuration      ErrorCategory = "duration_invalid"
	ErrFeedName      ErrorCategory = "feed_name_invalid"
	ErrFeedURL       ErrorCategory = "feed_url_invalid"
	ErrFeedThreshold ErrorCategory = "feed_threshold_invalid"
	ErrAllowlist     ErrorCategory = "allowlist_invalid"
	ErrPath          ErrorCategory = "path_invalid"
	ErrServer        ErrorCategory = "server_invalid"
	ErrNotification  ErrorCategory = "notification_invalid"
	ErrValidation    ErrorCategory = "validation_invalid"
)

// Error deliberately omits rejected values and wrapped error text.
type Error struct {
	Category ErrorCategory
	Field    string
	Index    int
	cause    error
}

func (e *Error) Error() string {
	if e == nil {
		return "configuration error"
	}
	if e.Field == "" {
		return fmt.Sprintf("configuration: %s", e.Category)
	}
	if e.Index >= 0 {
		return fmt.Sprintf("configuration %s[%d]: %s", e.Field, e.Index, e.Category)
	}
	return fmt.Sprintf("configuration %s: %s", e.Field, e.Category)
}

func (e *Error) Unwrap() error { return e.cause }

func configError(category ErrorCategory, field string, cause error) error {
	return &Error{Category: category, Field: field, Index: -1, cause: cause}
}

func indexedError(category ErrorCategory, field string, index int, cause error) error {
	return &Error{Category: category, Field: field, Index: index, cause: cause}
}

// IsCategory checks a configuration error without exposing its cause.
func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}
