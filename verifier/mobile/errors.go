package mobile

import (
	"errors"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/errs"
)

// mobileError restores the category prefix that an error's own Error method
// would have printed. gomobile flattens every error to an NSError carrying
// only a message, so errors.As is unavailable across the boundary and the
// category has to survive in the text.
func mobileError(err error) error {
	var category errs.Error
	if err == nil || !errors.As(err, &category) || err == category {
		return err
	}
	var prefix string
	switch category.(type) {
	case *errs.ConfigurationError:
		prefix = "configuration error: "
	case *errs.FetchError:
		prefix = "fetch error: "
	case *errs.AttestationError:
		prefix = "attestation error: "
	}
	return fmt.Errorf("%s%w", prefix, err)
}
