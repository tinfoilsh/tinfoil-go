package endorsement

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

const capturedRegistryFixture = "../../testdata/registry/canary-endorsement.json"
const capturedFreshnessDomain = "tinfoil-config-freshness/v1\x00"

func TestCapturedSigstoreEvidence(t *testing.T) {
	var registry struct {
		EndorsementRef string         `json:"endorsement_ref"`
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
	digest := sha256.Sum256(registry.Config)
	require.Equal(t, registry.Digest, hex.EncodeToString(digest[:]))
	require.Equal(t, registry.EndorsementRef, statement.EndorsementReference(payload))

	// Frozen evidence exercises Sigstore cryptography independently of the config schema.
	client, err := NewDefaultClient()
	require.NoError(t, err)
	keys, err := PublicSigningKeys()
	require.NoError(t, err)
	v, err := newEndorsementVerifier(client.trustRoot, keys)
	require.NoError(t, err)
	hint, err := v.Verify(&b, digest[:])
	require.NoError(t, err)
	const productionKeyHint = "J4/dwixneOvUPEEizF3WGcRiLOpQvzk5Kd8ThACLK60="
	require.Equal(t, productionKeyHint, hint)
	private, err := newEndorsementVerifier(client.trustRoot, []crypto.PublicKey{sigstoretest.New(t).Key.Public()})
	require.NoError(t, err)
	_, err = private.Verify(&b, digest[:])
	require.ErrorContains(t, err, "untrusted approval signing key")

	var core, predicate map[string]jsontext.Value
	require.NoError(t, json.Unmarshal(payload, &core))
	require.NoError(t, json.Unmarshal(core["predicate"], &predicate))
	var freshness struct {
		Timestamp []byte `json:"rfc3161Timestamp"`
	}
	require.NoError(t, json.Unmarshal(predicate["freshness"], &freshness))
	delete(predicate, "freshness")
	core["predicate"], err = json.Marshal(predicate)
	require.NoError(t, err)
	input, err := statement.TimestampInput(capturedFreshnessDomain, core)
	require.NoError(t, err)
	archived, err := newTimePolicy(time.Time{}, 0, 0, true)
	require.NoError(t, err)
	at, err := v.VerifyTimestamp(freshness.Timestamp, input, archived)
	require.NoError(t, err)
	require.False(t, at.IsZero())
	stale, err := newTimePolicy(at.Add(DefaultMaxAge+time.Nanosecond), 0, 0, false)
	require.NoError(t, err)
	_, err = v.VerifyTimestamp(freshness.Timestamp, input, stale)
	require.ErrorContains(t, err, "too old")
	_, err = v.VerifyTimestamp(freshness.Timestamp, append(input, 'x'), archived)
	require.ErrorContains(t, err, "does not match")
}
