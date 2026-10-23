// Package verifytest builds verify.Verification values for this module's
// tests without verifying a document.
package verifytest

import (
	"github.com/tinfoilsh/tinfoil-go/internal/verifyhook"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Fields are the facts the verification reports.
type Fields = verifyhook.Fields

// New returns a verification reporting f.
func New(f Fields) *verify.Verification {
	return verifyhook.NewVerification(f).(*verify.Verification)
}
