// Package validity combines the deadlines of authenticated verification inputs.
package validity

import "time"

// Earliest returns the earliest nonzero deadline, or zero if none is set.
func Earliest(times ...time.Time) time.Time {
	var earliest time.Time
	for _, t := range times {
		if !t.IsZero() && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	return earliest
}
