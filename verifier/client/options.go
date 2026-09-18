package client

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

// VerificationOptions defines immutable policy, copied when a client is created.
type VerificationOptions struct {
	// FreshnessMaxAge limits the age of both authenticated freshness witnesses.
	// Zero uses the seven-day default; negative values are invalid.
	FreshnessMaxAge time.Duration
}

func (o VerificationOptions) freshnessMaxAge() (time.Duration, error) {
	if o.FreshnessMaxAge < 0 {
		return 0, fmt.Errorf("freshness max age must not be negative")
	}
	if o.FreshnessMaxAge == 0 {
		return provenance.MaxFreshnessAge, nil
	}
	return o.FreshnessMaxAge, nil
}
