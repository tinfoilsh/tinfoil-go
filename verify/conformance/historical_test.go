//go:build tinfoil_conformance

package conformance

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

func TestFixturesHistoricalVerification(t *testing.T) {
	const outsideCollateralYears = 10
	dir := os.Getenv("TINFOIL_CONFORMANCE_FIXTURES")
	if dir == "" {
		t.Skip("requires shared golden fixtures")
	}
	for _, name := range []string{"golden-happy.json", "tdx-golden-happy.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if os.IsNotExist(err) {
				t.Skip("fixture belongs to another suite")
			}
			require.NoError(t, err)
			var f fixture
			require.NoError(t, json.Unmarshal(raw, &f))
			docBytes, err := base64.StdEncoding.DecodeString(f.Input.DocumentB64)
			require.NoError(t, err)
			nonce, err := hex.DecodeString(f.Input.NonceHex)
			require.NoError(t, err)
			roots, err := f.Input.roots()
			require.NoError(t, err)
			at := time.Unix(f.Input.VerificationTimeUnix, 0).UTC()
			newVerifier := func(opts ...verify.Option) *verify.Verifier {
				t.Helper()
				opts = append(opts, verify.DangerousTestOnlyWithSigstoreRoot(roots.sigstore), verify.DangerousTestOnlyWithVendorRoots(roots.amd, roots.intel))
				v, err := verify.NewVerifier(opts...)
				require.NoError(t, err)
				return v
			}
			archived := newVerifier(verify.WithVerificationTime(at))
			got, err := archived.VerifyV3(docBytes, nonce, f.Input.Repo)
			require.NoError(t, err)
			require.Equal(t, at, got.Metadata.VerifiedAt)
			require.True(t, got.FreshnessExpiresAt.After(at))
			tls, err := got.TLSPublicKeyFP()
			require.NoError(t, err)
			require.Equal(t, f.Expected.TLSPublicKeyFP, tls)

			for _, when := range []time.Time{at.Add(-time.Hour), got.FreshnessExpiresAt.Add(time.Second)} {
				_, layer, err := newVerifier(verify.WithVerificationTime(when)).VerifyV3WithLayer(docBytes, nonce, f.Input.Repo)
				require.Error(t, err)
				require.Equal(t, "provenance", layer)
			}
			_, err = newVerifier().VerifyV3(docBytes, nonce, f.Input.Repo)
			require.Error(t, err, "archived evidence must not pass at the current time")

			for _, id := range []string{collateral.FreshnessIDCode, collateral.FreshnessIDPlatform} {
				for _, remove := range []bool{false, true} {
					var wire map[string]any
					require.NoError(t, json.Unmarshal(docBytes, &wire))
					entries := wire["collateral"].([]any)
					for i, entry := range entries {
						item := entry.(map[string]any)
						if item["id"] == id {
							if remove {
								wire["collateral"] = append(entries[:i], entries[i+1:]...)
							} else {
								item["data"].(map[string]any)["sigstore_bundle"] = map[string]any{}
							}
							break
						}
					}
					modified, err := json.Marshal(wire)
					require.NoError(t, err)
					_, layer, err := archived.VerifyV3WithLayer(modified, nonce, f.Input.Repo)
					require.Error(t, err, "%s removed=%t", id, remove)
					require.Equal(t, "provenance", layer)
				}
			}

			doc, err := document.Parse(docBytes, nonce)
			require.NoError(t, err)
			for _, when := range []time.Time{at.AddDate(-outsideCollateralYears, 0, 0), at.AddDate(outsideCollateralYears, 0, 0)} {
				opts := &quote.Options{VerificationTime: when}
				opts.DangerousTestOnlySetRoots(roots.amd, roots.intel)
				_, err := quote.Authenticate(doc.CPUEvidence(), doc.CPUEndorsements(), opts)
				require.Error(t, err, "hardware collateral must be valid at appraisal")
			}
		})
	}
}
