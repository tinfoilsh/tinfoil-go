package enclave

import (
	"errors"
	"strings"
)

// HTTP adds context outside the SDK category. Restore its leading prefix for
// gomobile without replacing the category or losing the HTTP error's cause.
// The wrapped message already holds the category's own, so its prefix moves to
// the front rather than appearing twice.
func mobileError(err error) error {
	var category Error
	if !errors.As(err, &category) || err == category {
		return err
	}
	var prefix string
	switch category.(type) {
	case *ConfigurationError:
		prefix = "configuration error: "
	case *FetchError:
		prefix = "fetch error: "
	case *AttestationError:
		prefix = "attestation error: "
	}
	message := err.Error()
	if strings.HasPrefix(message, prefix) {
		return err
	}
	own := category.Error()
	message = strings.Replace(message, own, strings.TrimPrefix(own, prefix), 1)
	return &prefixedError{message: prefix + message, err: err}
}

type prefixedError struct {
	message string
	err     error
}

func (e *prefixedError) Error() string { return e.message }
func (e *prefixedError) Unwrap() error { return e.err }
