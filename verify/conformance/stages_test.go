//go:build tinfoil_conformance

package conformance

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

// approvalFixture is a synthetic Sigstore world for the approval and
// timestamp stages: a key-signed bundle over an in-toto statement, a
// timestamp from the fixture's TSA, and the trusted-root JSON the stage input
// carries. sigstoretest.Trust is a TrustedMaterial, not a serializable
// TrustedRoot, so the JSON is assembled from its parts (the TSA chain and the
// Rekor log) through root.NewTrustedRoot.
type approvalFixture struct {
	*sigstoretest.Fixture
	trustRootB64 string
	keyPEM       string
	hint         string
}

func newApprovalFixture(t *testing.T) approvalFixture {
	t.Helper()
	f := sigstoretest.New(t)
	trust, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, []root.TimestampingAuthority{f.Trust.TSA}, f.Trust.RekorLogs())
	require.NoError(t, err)
	trustJSON, err := trust.MarshalJSON()
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(f.Key.Public())
	require.NoError(t, err)
	hint, err := statement.KeyHint(f.Key.Public())
	require.NoError(t, err)
	return approvalFixture{
		Fixture:      f,
		trustRootB64: base64.StdEncoding.EncodeToString(trustJSON),
		keyPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		hint:         hint,
	}
}

// approvalInput is an accepting v3-authenticate-approval input: the bundle
// signs a statement whose subject carries digest.
func (f approvalFixture) approvalInput(t *testing.T, digest string) Input {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"_type":         statement.StatementType,
		"subject":       []map[string]any{{"name": "artifact", "digest": map[string]string{"sha256": digest}}},
		"predicateType": "https://tinfoil.sh/predicate/test/v1",
		"predicate":     map[string]any{},
	})
	require.NoError(t, err)
	bundleJSON := sigstoretest.MarshalBundle(t, f.Bundle(t, payload))
	return Input{
		SchemaVersion:          SchemaVersion,
		SigstoreTrustedRootB64: f.trustRootB64,
		BundleJSONB64:          base64.StdEncoding.EncodeToString(bundleJSON),
		SigningKeysPEM:         []string{f.keyPEM},
		ArtifactDigestHex:      digest,
	}
}

// timestampInput is an accepting v3-verify-timestamp input: a token over
// input minted at genTime, appraised at now.
func (f approvalFixture) timestampInput(t *testing.T, input []byte, genTime, now time.Time) Input {
	t.Helper()
	return Input{
		SchemaVersion:          SchemaVersion,
		SigstoreTrustedRootB64: f.trustRootB64,
		TimestampResponseB64:   base64.StdEncoding.EncodeToString(f.Timestamp(t, input, genTime)),
		TimestampInputB64:      base64.StdEncoding.EncodeToString(input),
		VerificationTimeUnix:   now.Unix(),
	}
}

func TestAuthenticateApprovalStage(t *testing.T) {
	f := newApprovalFixture(t)
	digest := strings.Repeat("ab", 32)

	t.Run("accept", func(t *testing.T) {
		out, code := Run(StageAuthenticateApproval, f.approvalInput(t, digest))
		require.Equal(t, ExitAccepted, code, "%+v", out.Rejection)
		require.True(t, out.Accepted)
		require.NotNil(t, out.Outputs)
		require.Equal(t, f.hint, out.Outputs.SigningKeyHint)
	})
	t.Run("malformed key", func(t *testing.T) {
		in := f.approvalInput(t, digest)
		in.SigningKeysPEM = []string{"-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n"}
		out, code := Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitMalformed, code)
		require.Equal(t, "MALFORMED_INPUT", out.Rejection.Code)
	})
	t.Run("no keys", func(t *testing.T) {
		in := f.approvalInput(t, digest)
		in.SigningKeysPEM = nil
		_, code := Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitMalformed, code)
	})
	t.Run("undecodable fields", func(t *testing.T) {
		in := f.approvalInput(t, digest)
		in.BundleJSONB64 = "%%%"
		_, code := Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitMalformed, code)
		in = f.approvalInput(t, digest)
		in.ArtifactDigestHex = "zz"
		_, code = Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitMalformed, code)
	})
	t.Run("wrong digest", func(t *testing.T) {
		in := f.approvalInput(t, digest)
		in.ArtifactDigestHex = strings.Repeat("cd", 32)
		out, code := Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitRejected, code)
		require.False(t, out.Accepted)
		require.Equal(t, "PROVENANCE_REJECTED", out.Rejection.Code)
	})
	t.Run("unpinned key", func(t *testing.T) {
		in := f.approvalInput(t, digest)
		in.SigningKeysPEM = []string{newApprovalFixture(t).keyPEM}
		out, code := Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitRejected, code)
		require.Equal(t, "PROVENANCE_REJECTED", out.Rejection.Code)
	})
	t.Run("unknown log", func(t *testing.T) {
		in := f.approvalInput(t, digest)
		in.SigstoreTrustedRootB64 = newApprovalFixture(t).trustRootB64
		out, code := Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitRejected, code)
		require.Equal(t, "PROVENANCE_REJECTED", out.Rejection.Code)
	})
	t.Run("ignores document fields", func(t *testing.T) {
		in := f.approvalInput(t, digest)
		in.DocumentB64, in.NonceHex = "%%%", "zz"
		_, code := Run(StageAuthenticateApproval, in)
		require.Equal(t, ExitAccepted, code)
	})
}

func TestVerifyTimestampStage(t *testing.T) {
	f := newApprovalFixture(t)
	input := []byte("tinfoil-approval-core")
	genTime := f.Now.Add(-time.Hour)

	t.Run("accept", func(t *testing.T) {
		out, code := Run(StageVerifyTimestamp, f.timestampInput(t, input, genTime, f.Now))
		require.Equal(t, ExitAccepted, code, "%+v", out.Rejection)
		require.True(t, out.Accepted)
		require.NotNil(t, out.Outputs)
		require.Equal(t, genTime.UTC().Format(time.RFC3339), out.Outputs.Timestamp)
		require.True(t, strings.HasSuffix(out.Outputs.Timestamp, "Z"))
	})
	t.Run("wrong input", func(t *testing.T) {
		in := f.timestampInput(t, input, genTime, f.Now)
		in.TimestampInputB64 = base64.StdEncoding.EncodeToString([]byte("other bytes"))
		out, code := Run(StageVerifyTimestamp, in)
		require.Equal(t, ExitRejected, code)
		require.Equal(t, "PROVENANCE_REJECTED", out.Rejection.Code)
	})
	t.Run("clock outside window", func(t *testing.T) {
		// Too old: the appraisal clock is more than 7 days past genTime.
		out, code := Run(StageVerifyTimestamp, f.timestampInput(t, input, genTime, genTime.Add(8*24*time.Hour)))
		require.Equal(t, ExitRejected, code)
		require.Equal(t, "PROVENANCE_REJECTED", out.Rejection.Code)
		// In the future: genTime is more than 5 minutes past the clock.
		out, code = Run(StageVerifyTimestamp, f.timestampInput(t, input, genTime, genTime.Add(-10*time.Minute)))
		require.Equal(t, ExitRejected, code)
		require.Equal(t, "PROVENANCE_REJECTED", out.Rejection.Code)
	})
	t.Run("unknown authority", func(t *testing.T) {
		in := f.timestampInput(t, input, genTime, f.Now)
		in.SigstoreTrustedRootB64 = newApprovalFixture(t).trustRootB64
		out, code := Run(StageVerifyTimestamp, in)
		require.Equal(t, ExitRejected, code)
		require.Equal(t, "PROVENANCE_REJECTED", out.Rejection.Code)
	})
	t.Run("missing clock", func(t *testing.T) {
		in := f.timestampInput(t, input, genTime, f.Now)
		in.VerificationTimeUnix = 0
		out, code := Run(StageVerifyTimestamp, in)
		require.Equal(t, ExitMalformed, code)
		require.Equal(t, "MALFORMED_INPUT", out.Rejection.Code)
	})
	t.Run("undecodable fields", func(t *testing.T) {
		in := f.timestampInput(t, input, genTime, f.Now)
		in.TimestampResponseB64 = "%%%"
		_, code := Run(StageVerifyTimestamp, in)
		require.Equal(t, ExitMalformed, code)
		in = f.timestampInput(t, input, genTime, f.Now)
		in.TimestampInputB64 = "%%%"
		_, code = Run(StageVerifyTimestamp, in)
		require.Equal(t, ExitMalformed, code)
	})
}

func TestNewStagesAdvertised(t *testing.T) {
	stages := Capabilities()["v3"].(map[string]any)["stages_supported"].([]string)
	require.Contains(t, stages, StageAuthenticateApproval)
	require.Contains(t, stages, StageVerifyTimestamp)
}
