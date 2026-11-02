package enclave

import (
	"errors"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// rejectedError is a VerificationCheck's rejection. It is a decision about
// the evidence, so an Enclave doesn't retry it.
type rejectedError struct {
	host string
	err  error
}

func (e *rejectedError) Error() string {
	return fmt.Sprintf("verification check rejected %s: %v", e.host, e.err)
}
func (e *rejectedError) Unwrap() error { return e.err }

// fromVerify reports a verify error in the SDK's categories by its outermost
// verify type: a UsageError is the caller's configuration error, and anything
// else verify rejects is an attestation failure. The verify error remains the
// cause.
func fromVerify(err error) error {
	if err == nil {
		return nil
	}
	var classified verify.Error
	if errors.As(err, &classified) {
		if _, usage := classified.(*verify.UsageError); usage {
			return errs.Configuration(err)
		}
	}
	return errs.Attestation(err)
}
