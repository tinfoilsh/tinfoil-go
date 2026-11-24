package verify

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

func TestCheckPinVerifiability(t *testing.T) {
	inputs := embeddedInputs(t)
	authorize := ConfigAuthorizer{Authorize: func(collateral.ConfigEndorsement) error { return nil }}
	for _, tc := range []struct {
		name   string
		config ConfigTrust
		pin    Pin
		valid  bool
	}{
		{"defaults with a project", nil, Pin{Project: "org/repo@v1"}, true},
		{"defaults with a repository", nil, Pin{Repo: "Org/My_Repo"}, true},
		{"defaults with both", nil, Pin{Repo: "Org/My_Repo", Project: "org/project"}, true},
		{"defaults without a pin", nil, Pin{}, false},
		{"named registry without a pin", Registries{IDs: []string{configendorsement.PublicRegistryID}}, Pin{}, true},
		{"defaults with a malformed project", nil, Pin{Project: "not a reference"}, false},
		{"defaults with a malformed repository", nil, Pin{Repo: "not a reference"}, false},
		{"embedded config without a pin", *inputs.Config, Pin{}, true},
		{"embedded config with its own project", *inputs.Config, Pin{Project: "org/project@v1"}, true},
		{"embedded config with another project", *inputs.Config, Pin{Project: "org/repo"}, false},
		{"embedded config with a repository alone", *inputs.Config, Pin{Repo: "org/project"}, false},
		{"embedded config with its own project and a repository", *inputs.Config, Pin{Repo: "org/project", Project: "org/project@v1"}, true},
		{"config authorizer without a pin", authorize, Pin{}, true},
		{"config authorizer with a project", authorize, Pin{Project: "org/repo"}, false},
		{"config authorizer with a repository", authorize, Pin{Repo: "org/repo"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifier(tc.config, Policy{})
			require.NoError(t, err)
			err = v.CheckPinVerifiability(tc.pin)
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
	v, err := NewVerifier(nil, Policy{})
	require.NoError(t, err)
	require.NoError(t, v.CheckPinVerifiability(Pin{Project: "Org/My_Repo"}))
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	_, err = v.VerifyV3(raw, nonce, Pin{Project: "Org/My_Repo"})
	var usage *UsageError
	require.ErrorAs(t, err, &usage)
	require.ErrorContains(t, err, "invalid config identity")
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
	v, err := NewVerifier(ConfigAuthorizer{Authorize: func(collateral.ConfigEndorsement) error { return refused }}, inputs.policy())
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, Pin{})
	var classified Error
	require.ErrorAs(t, err, &classified)
	require.IsType(t, &VerificationError{}, classified, "the outermost verify error is the type")
	require.Equal(t, LayerProvenance, classified.(*VerificationError).Layer)
	require.ErrorIs(t, err, refused, "the authorizer's error remains the cause")
	report := requireReport(t, err, LayerProvenance, time.Time{})
	require.Contains(t, report.Steps[1].Message, "authorizing config")
	require.Nil(t, report.PartialFacts.Expected)
}

func TestConfigAuthorizerPreservesReferencesAndHardwareChecks(t *testing.T) {
	inputs := embeddedInputs(t)
	digest := sha256.Sum256(inputs.Config.Bytes)
	data, err := json.Marshal(map[string][]byte{"config_base64": inputs.Config.Bytes})
	require.NoError(t, err)
	raw, nonce, doc := embeddedDocument(t, collateral.FormatV3, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: data})
	inputs.Config = nil
	v, err := newEmbeddedVerifier(inputs)
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
	v.configAuthorizer = authorize
	refs, err := v.configReferences(doc, "", time.Now())
	require.NoError(t, err)
	require.Equal(t, digest, refs.quote.(quote.ConfigReferenceValues).Hash)
	require.Equal(t, &ConfigVerification{Source: SourcePolicy, Digest: fmt.Sprintf("%x", digest)}, refs.config)
	_, err = v.configReferences(doc, "org/project", time.Now())
	require.ErrorContains(t, err, "cannot authenticate repository")
	result, err := v.VerifyV3(raw, nonce, Pin{})
	require.Nil(t, result)
	requireRejectedAt(t, err, LayerQuote)

	v.embedded.runtime = append(v.embedded.runtime, '\n')
	_, err = v.configReferences(doc, "", time.Now())
	require.ErrorContains(t, err, "config's digest pin")
	v.embedded.runtime = nil
	_, err = v.configReferences(doc, "", time.Now())
	require.ErrorIs(t, err, collateral.ErrNotFound)
	require.ErrorContains(t, err, collateral.RuntimeID)
	v.embedded.runtime = inputs.Runtime
	v.embedded.platform = nil
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

func TestConfigAuthorizerMustNotBeNil(t *testing.T) {
	_, err := NewVerifier(ConfigAuthorizer{}, Policy{})
	require.ErrorAs(t, err, new(*UsageError))
	require.ErrorContains(t, err, "must not be nil")
}
