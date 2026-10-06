package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
)

const capturedCanaryIdentity = "/tinfoil/registry-canary"

func TestCapturedRegistryTimestamp(t *testing.T) {
	var registry struct {
		EndorsementRef string         `json:"endorsement_ref"`
		AuditScope     string         `json:"audit_scope"`
		Name           string         `json:"name"`
		Digest         string         `json:"digest"`
		Config         []byte         `json:"config"`
		Bundle         jsontext.Value `json:"bundle"`
	}
	require.NoError(t, json.Unmarshal(capturedFixture(t, "registry", "canary-endorsement.json"), &registry))
	var b bundle.Bundle
	require.NoError(t, b.UnmarshalJSON(registry.Bundle))
	payload := b.GetDsseEnvelope().GetPayload()
	statement, err := endorsement.ParseStatement(payload)
	require.NoError(t, err)
	digest := sha256.Sum256(registry.Config)
	require.Equal(t, registry.Digest, hex.EncodeToString(digest[:]))
	require.Equal(t, registry.Digest, statement.Subject[0].Digest["sha256"])
	require.Equal(t, registry.Name, statement.Subject[0].Name)
	require.Equal(t, registry.AuditScope, statement.Predicate.AuditScope)
	ref, err := endorsement.EndorsementReference(payload)
	require.NoError(t, err)
	require.Equal(t, registry.EndorsementRef, ref)
	input, err := statement.TimestampInput()
	require.NoError(t, err)

	// This authenticates the production TSA token only. The generated key is
	// not registry trust, and this test does not authenticate the endorsement.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	client, err := provenance.NewDefaultClient()
	require.NoError(t, err)
	v, err := client.ConfigVerifier([]endorsement.SigningKey{{PublicKey: key.Public(), AuditScope: registry.AuditScope}})
	require.NoError(t, err)
	archived := endorsement.Policy{Identity: capturedCanaryIdentity, AuditScope: registry.AuditScope, IgnoreFreshness: true}
	at, err := v.VerifyTimestamp(input, statement.Predicate.Freshness.RFC3161Timestamp, archived)
	require.NoError(t, err)
	require.False(t, at.IsZero())
	stale := archived
	stale.IgnoreFreshness = false
	stale.Now = at.Add(endorsement.DefaultMaxAge + time.Nanosecond)
	_, err = v.VerifyTimestamp(input, statement.Predicate.Freshness.RFC3161Timestamp, stale)
	require.ErrorContains(t, err, "too old")
	_, err = v.VerifyTimestamp(append(input, 'x'), statement.Predicate.Freshness.RFC3161Timestamp, archived)
	require.ErrorContains(t, err, "does not match")
}
