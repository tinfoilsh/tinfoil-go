package client

import (
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

func TestFreshnessDeadlineUsesEarlierAuthenticatedWitness(t *testing.T) {
	issued := time.Date(2026, 9, 10, 22, 8, 7, 0, time.UTC)
	later := issued.Add(24 * time.Hour)
	for _, tc := range []struct {
		name           string
		code, platform time.Time
	}{
		{"code expires first", issued, later},
		{"platform expires first", later, issued},
		{"same issuance time", issued, issued},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := issued.Add(provenance.MaxFreshnessAge)
			if got := freshnessDeadline(tc.code, tc.platform); !got.Equal(want) {
				t.Fatalf("freshness deadline = %s, want %s", got, want)
			}
		})
	}
}
