package verify

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

func TestConfigAuthorizerPreservesReferencesAndHardwareChecks(t *testing.T) {
	inputs := embeddedInputs(t)
	digest := sha256.Sum256(inputs.Config.Bytes)
	data, err := json.Marshal(map[string][]byte{"config_base64": inputs.Config.Bytes})
	require.NoError(t, err)
	raw, nonce, doc := embeddedDocument(t, collateral.FormatV3, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: data})
	inputs.Config = nil
	v, err := NewVerifier(WithEmbeddedReferences(inputs))
	require.NoError(t, err)
	_, err = v.configReferences(doc, "org/project", time.Now())
	require.ErrorContains(t, err, "unsigned config")
	rejected := errors.New("config is not authorized")
	authorize := func(candidate collateral.ConfigEndorsement) error {
		if sha256.Sum256(candidate.Config) != digest {
			return rejected
		}
		candidate.Config[0] ^= 1
		return nil
	}
	require.NoError(t, WithConfigAuthorizer(authorize)(v))
	refs, err := v.configReferences(doc, "", time.Now())
	require.NoError(t, err)
	require.Equal(t, digest, refs.quote.(quote.ConfigReferenceValues).Hash)
	require.Equal(t, &ConfigVerification{Source: SourcePolicy, Digest: fmt.Sprintf("%x", digest)}, refs.config)
	_, err = v.configReferences(doc, "org/project", time.Now())
	require.ErrorContains(t, err, "cannot authenticate repository")
	result, layer, err := v.verifyV3(raw, nonce, "")
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, layerQuote, layer)

	v.embedded.Runtime = append(v.embedded.Runtime, '\n')
	_, err = v.configReferences(doc, "", time.Now())
	require.ErrorContains(t, err, "config's digest pin")
	v.embedded.Runtime = nil
	_, err = v.configReferences(doc, "", time.Now())
	require.ErrorIs(t, err, collateral.ErrNotFound)
	require.ErrorContains(t, err, collateral.RuntimeID)
	v.embedded.Runtime = inputs.Runtime
	v.embedded.Platform = nil
	_, err = v.configReferences(doc, "", time.Now())
	require.ErrorIs(t, err, collateral.ErrNotFound)
	require.ErrorContains(t, err, collateral.PlatformID)

	digest[0] ^= 1
	_, err = v.configReferences(doc, "", time.Now())
	require.ErrorIs(t, err, rejected)
	_, _, legacy := embeddedDocument(t, collateral.FormatV2)
	_, err = v.codeReferences(legacy, "org/project", time.Now())
	require.ErrorContains(t, err, "configured trust requires")
}

func TestConfigAuthorizerRejectsConflictingTrust(t *testing.T) {
	authorize := WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return nil })
	keys, err := endorsement.PublicSigningKeys()
	require.NoError(t, err)
	for _, options := range [][]Option{
		{WithConfigAuthorizer(nil)},
		{authorize, WithEmbeddedReferences(embeddedInputs(t))},
		{WithEmbeddedReferences(embeddedInputs(t)), authorize},
		{authorize, WithConfigSigningKeys(keys)},
		{WithConfigSigningKeys(keys), authorize},
	} {
		_, err := NewVerifier(options...)
		require.Error(t, err)
	}
}
