package endorsement

import (
	"fmt"
	"time"
)

const (
	DefaultMaxAge     = 7 * 24 * time.Hour
	DefaultFutureSkew = 5 * time.Minute
)

type timePolicy struct {
	earliest, latest time.Time
	ignoreFreshness  bool
}

func newTimePolicy(now time.Time, maxAge, futureSkew time.Duration, ignoreFreshness bool) (timePolicy, error) {
	if (now.IsZero() && !ignoreFreshness) || maxAge < 0 || futureSkew < 0 {
		return timePolicy{}, fmt.Errorf("clock and nonnegative age and skew are required")
	}
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	if futureSkew == 0 {
		futureSkew = DefaultFutureSkew
	}
	return timePolicy{earliest: now.Add(-maxAge), latest: now.Add(futureSkew), ignoreFreshness: ignoreFreshness}, nil
}

func (p timePolicy) verify(at time.Time) error {
	if p.ignoreFreshness {
		return nil
	}
	if at.Before(p.earliest) {
		return fmt.Errorf("approval is too old")
	}
	if at.After(p.latest) {
		return fmt.Errorf("timestamp is in the future")
	}
	return nil
}
