//go:build tinfoil_conformance

package mobile

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/conformance"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// TestConformanceVectorsMatchTheAdapter runs every full-verify vector under
// TINFOIL_CONFORMANCE_VECTORS (the suite's vectors/ directory, searched
// recursively) through the binding's test-only entry points and asserts the
// same verdict, rejection code and channel keys as Go's own adapter. Swift
// runs the same vectors through these entry points and asserts against the
// vectors' expectations.
//
// The binding rejects a result that is no longer fresh, as Go's client does,
// so it parts from the verifier at the one instant that a frozen clock can
// hit: a witness exactly at its maximum age, which the verifier accepts and
// the client treats as expired.
var bindingRejectsAtExpiry = map[string]bool{"fr2-pos-at-max-age.json": true}

func TestConformanceVectorsMatchTheAdapter(t *testing.T) {
	dir := os.Getenv("TINFOIL_CONFORMANCE_VECTORS")
	if dir == "" {
		t.Skip("set TINFOIL_CONFORMANCE_VECTORS to the conformance suite's vectors directory")
	}
	var files []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err == nil && filepath.Ext(path) == ".json" {
			files = append(files, path)
		}
		return err
	}))
	ran := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		// Every file must parse, so that a vector broken by an edit fails
		// here rather than drops out; only full-verify vectors are run.
		var fixture struct {
			Stage string         `json:"stage"`
			Input jsontext.Value `json:"input"`
		}
		require.NoError(t, json.Unmarshal(data, &fixture), file)
		if fixture.Stage != conformance.StageVerify {
			continue
		}
		var vector struct {
			Stage string
			Input conformance.Input
		}
		vector.Stage = fixture.Stage
		require.NoError(t, json.Unmarshal(fixture.Input, &vector.Input), file)
		ran++
		t.Run(filepath.Base(file), func(t *testing.T) {
			want, _ := conformance.Run(vector.Stage, vector.Input)
			roots, err := json.Marshal(conformanceRoots{
				SigstoreTrustedRootB64: vector.Input.SigstoreTrustedRootB64,
				AMDRootCAPEM:           vector.Input.AMDRootCAPEM,
				ASKPEM:                 vector.Input.ASKPEM,
				IntelSGXRootPEM:        vector.Input.IntelSGXRootPEM,
			})
			require.NoError(t, err)
			verifier, err := NewDangerousTestOnlyVerifier(string(roots))
			require.NoError(t, err)
			doc, err := base64.StdEncoding.DecodeString(vector.Input.DocumentB64)
			require.NoError(t, err)
			nonce, err := hex.DecodeString(vector.Input.NonceHex)
			require.NoError(t, err)
			at := vector.Input.VerificationTimeUnix
			require.NotZero(t, at, "every full-verify vector is frozen")

			payload, err := verifier.DangerousTestOnlyVerifyAt(doc, nonce, vector.Input.Repo, vector.Input.Project, at)
			if bindingRejectsAtExpiry[filepath.Base(file)] {
				require.True(t, want.Accepted)
				assert.ErrorContains(t, err, "freshness witnesses expired")
				return
			}
			if err != nil {
				// Only an error without a report is returned rather than
				// encoded in the result.
				code, _ := conformance.RejectionCode(err)
				require.NotNil(t, want.Rejection, "the binding rejected with %v where the adapter accepted", err)
				assert.Equal(t, "MALFORMED_INPUT", code, "%v", err)
				assert.Equal(t, want.Rejection.Code, code, "%v", err)
				return
			}
			result := decodeResult(t, payload)
			if want.Report != nil {
				require.Len(t, result.Report.Steps, len(want.Report.Steps))
				for i, s := range want.Report.Steps {
					assert.Equal(t, string(s.Layer), result.Report.Steps[i].Layer)
					assert.Equal(t, string(s.Status), result.Report.Steps[i].Status)
				}
			}
			if result.Error != nil {
				require.NotNil(t, want.Report, "the adapter reports every rejection by the verifier")
				require.NotNil(t, want.Rejection, "the binding rejected with %+v where the adapter accepted", result.Error)
				assert.Equal(t, want.Rejection.Code, strings.ToUpper(result.Error.Layer)+"_REJECTED")
				assert.Nil(t, result.Report.VerifiedFacts)
				require.NotNil(t, result.Report.PartialFacts)
				assert.Equal(t, want.Report.PartialFacts.Measured != nil, result.Report.PartialFacts.Measured != nil)
				assert.Equal(t, want.Report.PartialFacts.Expected != nil, result.Report.PartialFacts.Expected != nil)
				return
			}
			require.NotNil(t, result.Report.VerifiedFacts)
			got := result.Report.VerifiedFacts
			tlsFP := result.key(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
			hpke := result.key(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
			if tlsFP == "" || hpke == "" {
				// The adapter refuses a document without both channel keys
				// at the envelope; so does each client.
				require.NotNil(t, want.Rejection)
				assert.Equal(t, "ENVELOPE_REJECTED", want.Rejection.Code)
				return
			}
			require.True(t, want.Accepted, "the binding accepted where the adapter rejected with %+v", want.Rejection)
			assert.Equal(t, want.Outputs.CodeDigest, got.CodeDigest)
			assert.Equal(t, want.Outputs.TLSPublicKeyFP, tlsFP)
			assert.Equal(t, want.Outputs.HPKEPublicKey, hpke)
		})
	}
	require.NotZero(t, ran, "no full-verify vectors under %s", dir)
}

func TestDangerousTestOnlyVerifierRefusesBadRoots(t *testing.T) {
	for _, roots := range []string{
		`{"unknown":"x"}`,
		`{"sigstore_trusted_root_json_b64":"not base64"}`,
		`{"amd_root_ca_pem":"x"}`,
		`{"ask_pem":"x"}`,
		`{"sigstore_trusted_root_json_b64":"` + base64.StdEncoding.EncodeToString([]byte("{}")) + `"}`,
	} {
		_, err := NewDangerousTestOnlyVerifier(roots)
		assert.Error(t, err, roots)
	}
	_, err := NewDangerousTestOnlyVerifier(`{}`)
	assert.NoError(t, err, "no roots keeps the embedded anchors")
}
