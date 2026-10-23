// Package verifyhook carries package verify's test constructor to the rest of
// the module without exporting it. Use it through internal/verifytest.
package verifyhook

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Fields are the facts a test verification reports. They cover what tests
// outside package verify read.
type Fields struct {
	ConfigRepo         string
	CodeDigest         string
	CodeTag            string
	CodeMeasurement    measurement.Expected
	EnclaveMeasurement measurement.Measurement
	CryptoMaterial     []document.CryptoMaterialItem
	FreshnessExpiresAt time.Time
	VerifierName       string
	VerifierVersion    string
	VerifiedAt         time.Time
}

// NewVerification is installed by package verify and returns a
// *verify.Verification.
var NewVerification func(Fields) any
