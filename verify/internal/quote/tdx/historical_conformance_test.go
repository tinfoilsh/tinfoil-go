//go:build tinfoil_conformance

package tdx

import (
	"encoding/json/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHistoricalCollateral(t *testing.T) {
	raw, err := os.ReadFile("testdata/historical.json")
	require.NoError(t, err)
	var fixture struct {
		Time     time.Time `json:"verification_time"`
		Root     string    `json:"intel_root_pem"`
		Evidence Evidence  `json:"evidence"`
		Cases    map[string]struct {
			Bodies    map[string][]byte `json:"response_bodies"`
			WantError string            `json:"want_error"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))
	for name, tc := range fixture.Cases {
		t.Run(name, func(t *testing.T) {
			evidence := fixture.Evidence
			evidence.PCS = slices.Clone(evidence.PCS)
			for i := range evidence.PCS {
				if body, ok := tc.Bodies[evidence.PCS[i].URL]; ok {
					evidence.PCS[i].Body = body
				}
			}
			opts := &Options{VerificationTime: fixture.Time}
			opts.DangerousTestOnlySetRoot([]byte(fixture.Root))
			got, err := Authenticate(evidence, opts)
			if tc.WantError != "" {
				require.ErrorContains(t, err, tc.WantError)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			const expectedEvaluation = 18
			require.Equal(t, expectedEvaluation, got.tcbEvaluationDataNumber)
			require.Equal(t, strings.Repeat("55", 16), got.Identity())
		})
	}
}
