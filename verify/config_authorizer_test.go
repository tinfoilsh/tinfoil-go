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

func TestCheckRepoVerifiability(t *testing.T) {
	inputs := embeddedInputs(t)
	authorize := WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return nil })
	for _, tc := range []struct {
		name  string
		opts  []Option
		ref   string
		valid bool
	}{
		{"defaults with a pin", nil, "org/repo@v1", true},
		{"defaults with a pin only v2 collateral accepts", nil, "Org/My_Repo", true},
		{"defaults without a pin", nil, "", true},
		{"defaults with a malformed pin", nil, "not a reference", false},
		{"embedded config without a pin", []Option{WithEmbeddedReferences(inputs)}, "", true},
		{"embedded config with its own pin", []Option{WithEmbeddedReferences(inputs)}, "org/project@v1", true},
		{"embedded config with another pin", []Option{WithEmbeddedReferences(inputs)}, "org/repo", false},
		{"config authorizer without a pin", []Option{authorize}, "", true},
		{"config authorizer with a pin", []Option{authorize}, "org/repo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifier(tc.opts...)
			require.NoError(t, err)
			err = v.CheckRepoVerifiability(tc.ref)
			if tc.valid {
				require.NoError(t, err)
				return
			}
			var usage *UsageError
			require.ErrorAs(t, err, &usage)
		})
	}
}

func TestV3CollateralRequiresConfigIdentityPins(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	require.NoError(t, v.CheckRepoVerifiability("Org/My_Repo"))
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	_, err = v.VerifyV3(raw, nonce, "Org/My_Repo")
	var usage *UsageError
	require.ErrorAs(t, err, &usage)
	require.ErrorContains(t, err, "invalid config identity")
}

func TestCallerAuthorizesConfig(t *testing.T) {
	inputs := embeddedInputs(t)
	withoutConfig := inputs
	withoutConfig.Config = nil
	for _, tc := range []struct {
		name string
		opts []Option
		want bool
	}{
		{"defaults", nil, false},
		{"embedded runtime and platform", []Option{WithEmbeddedReferences(withoutConfig)}, false},
		{"embedded config", []Option{WithEmbeddedReferences(inputs)}, true},
		{"config authorizer", []Option{WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return nil })}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifier(tc.opts...)
			require.NoError(t, err)
			require.Equal(t, tc.want, v.CallerAuthorizesConfig())
		})
	}
}

// A config authorizer's error is the cause of a VerificationError. It never
// chooses verify's error type, even when it is one of verify's own types.
func TestConfigAuthorizerErrorNeverChoosesTheType(t *testing.T) {
	inputs := embeddedInputs(t)
	data, err := json.Marshal(map[string][]byte{"config_base64": inputs.Config.Bytes})
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: data})
	inputs.Config = nil
	refused := &UsageError{Err: errors.New("config is not authorized")}
	v, err := NewVerifier(WithEmbeddedReferences(inputs), WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return refused }))
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, "")
	var classified Error
	require.ErrorAs(t, err, &classified)
	require.IsType(t, &VerificationError{}, classified, "the outermost verify error is the type")
	require.Equal(t, LayerProvenance, classified.(*VerificationError).Layer)
	require.ErrorIs(t, err, refused, "the authorizer's error remains the cause")
}

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
	result, err := v.VerifyV3(raw, nonce, "")
	require.Nil(t, result)
	requireRejectedAt(t, err, LayerQuote)

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
