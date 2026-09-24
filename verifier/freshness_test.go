package verifier

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

func TestFreshnessExpiration(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	later := issuedAt.Add(time.Hour)
	for _, tt := range []struct {
		name                string
		codeWitnessedAt     time.Time
		platformWitnessedAt time.Time
	}{
		{"code expires first", issuedAt, later},
		{"platform expires first", later, issuedAt},
		{"same issuance time", issuedAt, issuedAt},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, maxAge := range []time.Duration{24 * time.Hour, provenance.MaxFreshnessAge, 30 * 24 * time.Hour} {
				require.Equal(t, issuedAt.Add(maxAge), freshnessExpiration(tt.codeWitnessedAt, tt.platformWitnessedAt, maxAge))
			}
		})
	}
}
