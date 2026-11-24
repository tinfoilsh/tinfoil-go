//go:build tinfoil_conformance

package conformance

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// updateGolden rewrites the report member of the golden files that name a
// vector from what the verifier reports for it.
var updateGolden = flag.Bool("update", false, "rewrite the report JSON golden files")

// TestReportJSONGoldenVectors checks the JSON form of the report of each
// full-verify vector that a golden file in verify/testdata/report-json names
// against the file's report.
func TestReportJSONGoldenVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "testdata", "report-json", "*.json"))
	require.NoError(t, err)
	ran := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		var golden map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &golden))
		var vector string
		if raw, ok := golden["vector"]; ok {
			require.NoError(t, json.Unmarshal(raw, &vector))
		}
		if vector == "" {
			continue
		}
		ran++
		t.Run(filepath.Base(file), func(t *testing.T) {
			report, err := verifyVector(t, vector)
			if err != nil {
				var rejected *verify.VerificationError
				require.ErrorAs(t, err, &rejected)
				report = rejected.Report
			}
			got, err := json.Marshal(report)
			require.NoError(t, err)
			if *updateGolden {
				golden["report"] = got
				out, err := json.MarshalIndent(golden, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(file, append(out, '\n'), 0o644))
				return
			}
			require.JSONEq(t, string(golden["report"]), string(got))
		})
	}
	require.NotZero(t, ran, "no golden file names a vector")
}
