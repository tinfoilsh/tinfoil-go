package endorsement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

const capturedRegistryFixture = "../../testdata/registry/canary-endorsement.json"

func TestCapturedRegistryTimestamp(t *testing.T) {
	var registry struct {
		EndorsementRef string         `json:"endorsement_ref"`
		AuditScope     string         `json:"audit_scope"`
		Name           string         `json:"name"`
		Digest         string         `json:"digest"`
		Config         []byte         `json:"config"`
		Bundle         jsontext.Value `json:"bundle"`
	}
	data, err := os.ReadFile(capturedRegistryFixture)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &registry))
	var b bundle.Bundle
	require.NoError(t, b.UnmarshalJSON(registry.Bundle))
	payload := b.GetDsseEnvelope().GetPayload()
	statement, err := configendorsement.ParseStatement(payload)
	require.NoError(t, err)
	digest := sha256.Sum256(registry.Config)
	require.Equal(t, registry.Digest, hex.EncodeToString(digest[:]))
	require.Equal(t, registry.Digest, statement.Subject[0].Digest["sha256"])
	require.Equal(t, registry.Name, statement.Subject[0].Name)
	require.Equal(t, registry.AuditScope, statement.Predicate.AuditScope)
	ref, err := configendorsement.EndorsementReference(payload)
	require.NoError(t, err)
	require.Equal(t, registry.EndorsementRef, ref)
	input, err := statement.TimestampInput()
	require.NoError(t, err)

	// This authenticates the production TSA token only, not the endorsement.
	client, err := NewDefaultClient()
	require.NoError(t, err)
	v := &endorsementVerifier{trust: client.trustRoot}
	archived, err := newTimePolicy(time.Time{}, 0, 0, true)
	require.NoError(t, err)
	at, err := v.VerifyTimestamp(statement.Predicate.Freshness.RFC3161Timestamp, input, archived)
	require.NoError(t, err)
	require.False(t, at.IsZero())
	stale, err := newTimePolicy(at.Add(DefaultMaxAge+time.Nanosecond), 0, 0, false)
	require.NoError(t, err)
	_, err = v.VerifyTimestamp(statement.Predicate.Freshness.RFC3161Timestamp, input, stale)
	require.ErrorContains(t, err, "too old")
	_, err = v.VerifyTimestamp(statement.Predicate.Freshness.RFC3161Timestamp, append(input, 'x'), archived)
	require.ErrorContains(t, err, "does not match")
}
