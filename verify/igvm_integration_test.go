//go:build tinfoil_conformance

package verify

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

type igvmSignedFixture struct {
	VerificationTime time.Time      `json:"verification_time"`
	NonceHex         string         `json:"nonce_hex"`
	SigstoreRoot     jsontext.Value `json:"sigstore_root"`
	AMDTrustPEM      string         `json:"amd_root_ca_pem"`
	ConfigKeyPEM     string         `json:"config_public_key_pem"`
	ConfigPolicy     ConfigPolicy   `json:"config_policy"`
	Document         jsontext.Value `json:"document"`
	WrongHostData    string         `json:"wrong_host_data_report_base64"`
	Expected         struct {
		RuntimeDigest string `json:"runtime_digest"`
		RuntimeTag    string `json:"runtime_tag"`
		ConfigDigest  string `json:"config_digest"`
		Measurement   string `json:"measurement"`
		TLSKey        string `json:"tls_public_key_fp"`
		HPKEKey       string `json:"hpke_public_key"`
	} `json:"expected"`
}

func TestVerifyIGVMSignedSNPDocument(t *testing.T) {
	// The frozen fixture uses genuine signatures under synthetic trust roots:
	// GitHub workflow certificates with SCTs, Rekor proofs, an inner TSA token,
	// and an AMD chain, CRL, and report. No private keys are needed to replay it.
	data, err := os.ReadFile("testdata/igvm-snp.json")
	require.NoError(t, err)
	var f igvmSignedFixture
	require.NoError(t, json.Unmarshal(data, &f))
	block, rest := pem.Decode([]byte(f.ConfigKeyPEM))
	require.NotNil(t, block)
	require.Empty(t, rest)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(f.NonceHex)
	require.NoError(t, err)
	now := f.VerificationTime
	v, err := NewVerifier(
		WithConfigSigningKeys([]endorsement.SigningKey{{PublicKey: key, AuditScope: f.ConfigPolicy.AuditScope}}),
		DangerousTestOnlyWithSigstoreRoot(f.SigstoreRoot),
		DangerousTestOnlyWithVendorRoots([]byte(f.AMDTrustPEM), nil),
		DangerousTestOnlyWithClock(func() time.Time { return now }),
		WithSoftwareIdentity(SoftwareIdentity{Name: "test-sdk", Version: "1.0.0"}),
	)
	require.NoError(t, err)

	t.Run("complete approval and hardware binding", func(t *testing.T) {
		got, err := v.VerifyIGVM(f.Document, nonce, f.ConfigPolicy)
		require.NoError(t, err)
		require.NotNil(t, got.Config)
		require.Equal(t, f.ConfigPolicy.Identity+"/"+f.ConfigPolicy.Revision, got.Config.Name)
		require.Equal(t, f.ConfigPolicy.AuditScope, got.Config.AuditScope)
		require.Equal(t, f.Expected.ConfigDigest, got.Config.Digest)
		require.Equal(t, f.Expected.RuntimeDigest, got.CodeDigest)
		require.Equal(t, f.Expected.RuntimeTag, got.CodeTag)
		require.Equal(t, "tinfoilsh/cvmimage", got.ConfigRepo)
		require.Equal(t, VerificationMetadata{Verifier: v.Identity(), VerifiedAt: now}, got.Metadata)
		wantMeasurement := &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{f.Expected.Measurement}}
		require.Equal(t, wantMeasurement, got.CodeMeasurement)
		require.Equal(t, wantMeasurement, got.EnclaveMeasurement)
		tlsKey, err := got.TLSPublicKeyFP()
		require.NoError(t, err)
		require.Equal(t, f.Expected.TLSKey, tlsKey)
		hpkeKey, err := got.HPKEPublicKey()
		require.NoError(t, err)
		require.Equal(t, f.Expected.HPKEKey, hpkeKey)
		approvedAt := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
		require.Equal(t, approvedAt, got.Config.ApprovalTime)
		require.Equal(t, approvedAt.Add(v.FreshnessMaxAge()), got.FreshnessExpiresAt)
	})

	t.Run("authentic report for another config", func(t *testing.T) {
		var doc, cpu map[string]jsontext.Value
		require.NoError(t, json.Unmarshal(f.Document, &doc))
		require.NoError(t, json.Unmarshal(doc["cpu_evidence"], &cpu))
		cpu["report_base64"], err = json.Marshal(f.WrongHostData)
		require.NoError(t, err)
		doc["cpu_evidence"], err = json.Marshal(cpu)
		require.NoError(t, err)
		altered, err := json.Marshal(doc)
		require.NoError(t, err)
		got, err := v.VerifyIGVM(altered, nonce, f.ConfigPolicy)
		require.ErrorContains(t, err, "HOST_DATA")
		require.Nil(t, got)
	})

	t.Run("expired approval", func(t *testing.T) {
		now = f.VerificationTime.Add(v.FreshnessMaxAge())
		got, err := v.VerifyIGVM(f.Document, nonce, f.ConfigPolicy)
		require.ErrorContains(t, err, "config approval is too old")
		require.Nil(t, got)
	})
}
