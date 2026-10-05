package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
)

// testdata/registry/canary-endorsement.json is what the production config
// registry served for its canary, saved verbatim, and is appraised below
// against the production Sigstore root. Its signature is not checked: that
// needs the registry's verification key, which is not published.

type registryEndorsement struct {
	EndorsementRef string         `json:"endorsement_ref"`
	AuditScope     string         `json:"audit_scope"`
	Name           string         `json:"name"`
	Digest         string         `json:"digest"`
	Config         string         `json:"config"`
	Bundle         jsontext.Value `json:"bundle"`
}

const canaryIdentity = "/tinfoil/registry-canary"

func canary(t *testing.T) (registryEndorsement, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "registry", "canary-endorsement.json"))
	require.NoError(t, err)
	var e registryEndorsement
	require.NoError(t, json.Unmarshal(data, &e))
	config, err := base64.StdEncoding.DecodeString(e.Config)
	require.NoError(t, err)
	return e, config
}

// canaryVerifier builds a config verifier over the production Sigstore root.
// Its signing key is generated here and is not the registry's; the checks
// below need a verifier, not that key.
func canaryVerifier(t *testing.T, scope string) *endorsement.Verifier {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	client, err := provenance.NewDefaultClient()
	require.NoError(t, err)
	v, err := client.ConfigVerifier([]endorsement.SigningKey{{PublicKey: key.Public(), AuditScope: scope}})
	require.NoError(t, err)
	return v
}

// The digest the registry publishes is SHA-256 of the exact config bytes,
// which is the value a guest writes into HOST_DATA or MRCONFIGID.
func TestRegistryCanaryDigestIsTheLaunchBinding(t *testing.T) {
	e, config := canary(t)
	digest := sha256.Sum256(config)
	assert.Equal(t, e.Digest, hex.EncodeToString(digest[:]))
}

// The statement the registry signs parses under this module's profile, down to
// the inner approval timestamp that makes withdrawal observable.
func TestRegistryCanaryStatementParses(t *testing.T) {
	e, _ := canary(t)
	var bundle struct {
		DSSE struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	require.NoError(t, json.Unmarshal(e.Bundle, &bundle))
	payload, err := base64.StdEncoding.DecodeString(bundle.DSSE.Payload)
	require.NoError(t, err)

	statement, err := endorsement.ParseStatement(payload)
	require.NoError(t, err)
	assert.Equal(t, e.Name, statement.Subject[0].Name)
	assert.Equal(t, e.Digest, statement.Subject[0].Digest["sha256"])
	assert.Equal(t, e.AuditScope, statement.Predicate.AuditScope)
	require.NotNil(t, statement.Predicate.Freshness)

	identity, revision, err := endorsement.ParseName(statement.Subject[0].Name)
	require.NoError(t, err)
	assert.Equal(t, canaryIdentity, identity)
	assert.NotEmpty(t, revision)

	// The reference the registry indexes by is derived from the signed bytes,
	// so a client that fetched by reference got the statement it asked for.
	ref, err := endorsement.EndorsementReference(payload)
	require.NoError(t, err)
	assert.Equal(t, e.EndorsementRef, ref)
}

// The approval time is authenticated against the public Sigstore timestamp
// authority in the embedded root, which needs no registry key.
func TestRegistryCanaryApprovalTimeIsAuthentic(t *testing.T) {
	e, _ := canary(t)
	var bundle struct {
		DSSE struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	require.NoError(t, json.Unmarshal(e.Bundle, &bundle))
	payload, err := base64.StdEncoding.DecodeString(bundle.DSSE.Payload)
	require.NoError(t, err)
	statement, err := endorsement.ParseStatement(payload)
	require.NoError(t, err)
	input, err := statement.TimestampInput()
	require.NoError(t, err)

	v := canaryVerifier(t, e.AuditScope)
	pin := endorsement.Policy{Identity: canaryIdentity, AuditScope: e.AuditScope}

	// Without an age bound, so this test does not start failing once the
	// canary is a week old.
	ignoring := pin
	ignoring.IgnoreFreshness = true
	approvedAt, err := v.VerifyTimestamp(input, statement.Predicate.Freshness.RFC3161Timestamp, ignoring)
	require.NoError(t, err)
	assert.False(t, approvedAt.IsZero())
	assert.True(t, approvedAt.After(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)), "approved at %s", approvedAt)

	// The age bound is live: judged long enough after the approval, the same
	// token is refused, which is how a withdrawn config stops verifying.
	stale := pin
	stale.Now = approvedAt.Add(8 * 24 * time.Hour)
	_, err = v.VerifyTimestamp(input, statement.Predicate.Freshness.RFC3161Timestamp, stale)
	require.ErrorContains(t, err, "too old")

	// And a token is bound to the statement it timestamps.
	_, err = v.VerifyTimestamp(append(input, 'x'), statement.Predicate.Freshness.RFC3161Timestamp, ignoring)
	require.ErrorContains(t, err, "imprint")
}

// Reaching the signing-key check proves the bundle's shape was accepted: the
// v0.3 media type, the single signature, the key hint and the Rekor v2
// inclusion proof are all that stands before it.
func TestRegistryCanaryBundleShapeIsAccepted(t *testing.T) {
	e, config := canary(t)
	v := canaryVerifier(t, e.AuditScope)
	_, err := v.Verify(config, e.Bundle, endorsement.Policy{
		Identity: canaryIdentity, AuditScope: e.AuditScope, Now: time.Now(),
	})
	require.ErrorContains(t, err, "signer is not authorized",
		"the bundle's shape must be accepted; only the key should be unknown")
}

// The verifier reads nothing out of a config but its digest, so the canary is
// usable as it stands even though its cvm-version names a release.
func TestRegistryCanaryNeedsNoRuntimePin(t *testing.T) {
	e, config := canary(t)
	digest := sha256.Sum256(config)
	assert.Equal(t, e.Digest, hex.EncodeToString(digest[:]))
	assert.Contains(t, string(config), "cvm-version: 0.11.0",
		"the member exists and is deliberately not read")
}
