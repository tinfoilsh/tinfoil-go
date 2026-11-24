package verify

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

const embeddedConfigName = "/org/project/v1"

func TestConfigPinsOneRuntimeManifest(t *testing.T) {
	_, _, doc := embeddedDocument(t, collateral.FormatV3)
	for _, suffix := range []string{"", "+gpu", "+mini", "+containers.initrd-1"} {
		inputs := embeddedInputs(t)
		var manifest runtime.Manifest
		require.NoError(t, json.Unmarshal(inputs.Runtime, &manifest))
		manifest.Version += suffix
		if suffix != "" {
			manifest.Measurements.SNPLaunch.Measurement = strings.Repeat("ef", runtime.MeasurementSize)
			manifest.Measurements.TDXLaunch.MRTD = strings.Repeat("12", runtime.MeasurementSize)
		}
		var err error
		inputs.Runtime, err = json.Marshal(manifest)
		require.NoError(t, err)
		inputs.Config.Bytes = []byte(fmt.Sprintf(`{"cvm-version":"0.15.0%s@sha256:%x"}`, suffix, sha256.Sum256(inputs.Runtime)))
		v, err := newEmbeddedVerifier(inputs)
		require.NoError(t, err)
		refs, err := v.configReferences(doc, "", time.Now())
		require.NoError(t, err)
		values := refs.quote.(quote.ConfigReferenceValues)
		require.Equal(t, sha256.Sum256(inputs.Config.Bytes), values.Hash)
		require.Equal(t, manifest.Measurements, values.Runtime)
		require.Equal(t, "v0.15.0", refs.artifact.Tag)
		inputs.Runtime = embeddedInputs(t).Runtime
		if suffix != "" {
			_, err = newEmbeddedVerifier(inputs)
			require.ErrorContains(t, err, "digest pin")
		}
	}
}

// embeddedTestInputs are caller-trusted references: a config, given as bytes
// or as a reference, and the runtime and platform artifacts. A nil member
// keeps the endorsement of that component.
type embeddedTestInputs struct {
	Config          *EmbeddedConfig
	ConfigReference *EmbeddedConfigReference
	Runtime         []byte
	Platform        []byte
}

// config returns the config trust that in selects.
func (in embeddedTestInputs) config() ConfigTrust {
	switch {
	case in.Config != nil:
		return *in.Config
	case in.ConfigReference != nil:
		return *in.ConfigReference
	}
	return nil
}

// policy returns a policy that embeds in's artifacts.
func (in embeddedTestInputs) policy() Policy {
	if in.Runtime == nil && in.Platform == nil {
		return Policy{}
	}
	return Policy{Artifacts: EmbeddedArtifacts{Runtime: in.Runtime, Platform: in.Platform}}
}

func newEmbeddedVerifier(in embeddedTestInputs) (*Verifier, error) {
	return NewVerifier(in.config(), in.policy())
}

func embeddedInputs(t *testing.T) embeddedTestInputs {
	t.Helper()
	zero := strings.Repeat("00", runtime.MeasurementSize)
	manifest, err := json.Marshal(runtime.Manifest{Version: "v0.15.0", Measurements: &runtime.Measurements{
		FormatVersion: runtime.FormatVersion,
		SNPLaunch:     &runtime.SNPLaunch{Measurement: strings.Repeat("ab", runtime.MeasurementSize)},
		TDXLaunch:     &runtime.TDXLaunch{MRTD: strings.Repeat("cd", runtime.MeasurementSize), RTMR0: zero, RTMR1: zero, RTMR2: zero, RTMR3: zero},
	}})
	require.NoError(t, err)
	platform, err := json.Marshal(policy.Artifact{Format: policy.ArtifactFormatV2})
	require.NoError(t, err)
	return embeddedTestInputs{
		Config:  &EmbeddedConfig{Name: embeddedConfigName, Bytes: []byte(fmt.Sprintf(`{"cvm-version":"0.15.0@sha256:%x"}`, sha256.Sum256(manifest)))},
		Runtime: manifest, Platform: platform,
	}
}

func TestEmbeddedConfigReferenceWithoutConfigBytes(t *testing.T) {
	inputs := embeddedInputs(t)
	digest := sha256.Sum256(inputs.Config.Bytes)
	runtime, err := configendorsement.RuntimeFromConfig(inputs.Config.Bytes)
	require.NoError(t, err)
	reference := EmbeddedConfigReference{Name: embeddedConfigName, Digest: hex.EncodeToString(digest[:]), Runtime: runtime}
	inputs.ConfigReference = &reference
	inputs.Config = nil
	v, err := newEmbeddedVerifier(inputs)
	require.NoError(t, err)
	require.NoError(t, v.CheckPinVerifiability(Pin{}))
	require.NoError(t, v.CheckPinVerifiability(Pin{Project: "org/project@v1@sha256:" + reference.Digest}))
	require.ErrorAs(t, v.CheckPinVerifiability(Pin{Project: "org/project@v2"}), new(*UsageError))
	require.ErrorAs(t, v.CheckPinVerifiability(Pin{Project: "org/project@sha256:" + strings.Repeat("ab", sha256.Size)}), new(*UsageError))
	raw, nonce, doc := embeddedDocument(t, collateral.FormatV3)
	refs, err := v.configReferences(doc, "org/project@v1", time.Now())
	require.NoError(t, err)
	require.Equal(t, digest, refs.quote.(quote.ConfigReferenceValues).Hash)
	require.Equal(t, runtime.Digest, refs.artifact.Digest)
	_, err = v.VerifyV3(raw, nonce, Pin{Project: "org/project@v1"})
	requireRejectedAt(t, err, LayerQuote)
	_, err = v.VerifyV3(raw, nonce, Pin{})
	requireRejectedAt(t, err, LayerQuote)
	for _, mutate := range []func(*EmbeddedConfigReference){
		func(r *EmbeddedConfigReference) { r.Digest = "" },
		func(r *EmbeddedConfigReference) { r.Runtime.Digest = strings.Repeat("cd", sha256.Size) },
		func(r *EmbeddedConfigReference) { r.Name = "/invalid" },
	} {
		bad := reference
		mutate(&bad)
		inputs.ConfigReference = &bad
		_, err = newEmbeddedVerifier(inputs)
		require.Error(t, err)
	}
	reference.Digest = strings.Repeat("ab", sha256.Size)
	got, err := v.configReferences(doc, "org/project@v1", time.Now())
	require.NoError(t, err)
	require.Equal(t, refs, got)
}

func embeddedDocument(t *testing.T, format string, entries ...collateral.Entry) ([]byte, []byte, *document.Document) {
	t.Helper()
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: format, Collateral: entries}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("unauthenticated quote"), nil
	})
	require.NoError(t, err)
	doc, err := document.Parse(raw, nonce)
	require.NoError(t, err)
	return raw, nonce, doc
}

func TestEmbeddedTrustPreservesBindingsAndOwnsItsBytes(t *testing.T) {
	inputs := embeddedInputs(t)
	configHash := sha256.Sum256(inputs.Config.Bytes)
	v, err := newEmbeddedVerifier(inputs)
	require.NoError(t, err)
	inputs.Config.Name = "/other/project/v2"
	for _, data := range [][]byte{inputs.Config.Bytes, inputs.Runtime, inputs.Platform} {
		data[0] ^= 1
	}
	raw, nonce, doc := embeddedDocument(t, collateral.FormatV3)
	refs, err := v.configReferences(doc, "org/project@v1@sha256:"+hex.EncodeToString(configHash[:]), time.Now())
	require.NoError(t, err)
	values := refs.quote.(quote.ConfigReferenceValues)
	require.Equal(t, configHash, values.Hash)
	require.Equal(t, strings.Repeat("ab", runtime.MeasurementSize), values.Runtime.SNPLaunch.Measurement)
	require.Equal(t, policy.ArtifactFormatV2, values.Endorsements.Format)
	require.Equal(t, SourceEmbedded, refs.config.Source)
	require.Equal(t, SourceEmbedded, refs.artifact.Source)
	require.Equal(t, SourceEmbedded, refs.platform.Source)
	require.Empty(t, refs.config.Reference)
	require.Empty(t, refs.config.SigningKeyHint)
	require.True(t, refs.config.ApprovalTime.IsZero())
	require.True(t, refs.freshnessExpiresAt.IsZero())
	result, err := v.VerifyV3(raw, nonce, Pin{Project: "org/project@v1"})
	require.Nil(t, result)
	requireRejectedAt(t, err, LayerQuote, "embedding must never bypass hardware authentication")
	_, err = v.VerifyV3(raw, nonce, Pin{})
	requireRejectedAt(t, err, LayerQuote, "exact local bytes can identify a workload without a registry pin")
}

func TestEmbeddedConfigCannotOverridePins(t *testing.T) {
	inputs := embeddedInputs(t)
	v, err := newEmbeddedVerifier(inputs)
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	for _, ref := range []string{"other/project", "org/project@v2", "org/project@sha256:" + strings.Repeat("00", sha256.Size)} {
		_, err := v.VerifyV3(raw, nonce, Pin{Project: ref})
		var usage *UsageError
		require.ErrorAs(t, err, &usage, "a pin the embedded config cannot meet is the caller's mistake")
		require.ErrorContains(t, err, "does not match the caller's pins")
	}
	inputs.Runtime = append(inputs.Runtime, '\n')
	_, err = newEmbeddedVerifier(inputs)
	require.ErrorAs(t, err, new(*UsageError), "a manifest the embedded config does not pin is the caller's mistake")
	require.ErrorContains(t, err, "config's digest pin")

	inputs = embeddedInputs(t)
	inputs.Config.Name = ""
	v, err = newEmbeddedVerifier(inputs)
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, Pin{Project: "org/project"})
	var usage *UsageError
	require.ErrorAs(t, err, &usage)
	require.ErrorContains(t, err, "does not match the caller's pins")
	_, err = v.VerifyV3(raw, nonce, Pin{})
	requireRejectedAt(t, err, LayerQuote)
}

func TestEmbeddedTrustStillRequiresOtherEndorsements(t *testing.T) {
	_, _, doc := embeddedDocument(t, collateral.FormatV3)
	for _, component := range []string{collateral.ConfigID, collateral.RuntimeID, collateral.PlatformID} {
		t.Run(component, func(t *testing.T) {
			inputs := embeddedInputs(t)
			switch component {
			case collateral.ConfigID:
				inputs.Config = nil
			case collateral.RuntimeID:
				inputs.Runtime = nil
			case collateral.PlatformID:
				inputs.Platform = nil
			}
			v, err := newEmbeddedVerifier(inputs)
			require.NoError(t, err)
			_, err = v.configReferences(doc, "org/project", time.Now())
			require.ErrorIs(t, err, collateral.ErrNotFound)
			require.ErrorContains(t, err, component)
		})
	}
}

func TestEmbeddedTrustRejectsInvalidOrUnusedInputs(t *testing.T) {
	inputs := embeddedInputs(t)
	keys, err := endorsement.PublicSigningKeys()
	require.NoError(t, err)
	for _, config := range []ConfigTrust{EmbeddedConfig{}, EmbeddedConfig{Bytes: make([]byte, configendorsement.MaxConfigSize+1)}, EmbeddedConfigReference{}} {
		_, err := NewVerifier(config, Policy{})
		require.ErrorAs(t, err, new(*UsageError))
	}
	for _, artifacts := range []EmbeddedArtifacts{
		{},
		{FreshnessKeys: keys},
		{Runtime: []byte{}},
		{Runtime: []byte(`{}`)},
		{Platform: []byte{}},
		{Platform: []byte(`{"format":"unknown"}`)},
		{Runtime: inputs.Runtime, FreshnessKeys: []crypto.PublicKey{}},
		// Keys with nothing left to verify.
		{Runtime: inputs.Runtime, Platform: inputs.Platform, FreshnessKeys: keys},
	} {
		_, err := NewVerifier(nil, Policy{Artifacts: artifacts})
		require.ErrorAs(t, err, new(*UsageError))
	}
	for _, artifacts := range []EmbeddedArtifacts{
		{Runtime: inputs.Runtime, FreshnessKeys: keys},
		{Platform: inputs.Platform, FreshnessKeys: keys},
	} {
		_, err := NewVerifier(*inputs.Config, Policy{Artifacts: artifacts})
		require.NoError(t, err)
	}
	for _, version := range []string{"", "0.15.0", "v0.15"} {
		var manifest runtime.Manifest
		require.NoError(t, json.Unmarshal(inputs.Runtime, &manifest))
		manifest.Version = version
		data, err := json.Marshal(manifest)
		require.NoError(t, err)
		_, err = NewVerifier(nil, Policy{Artifacts: EmbeddedArtifacts{Runtime: data}})
		require.ErrorAs(t, err, new(*UsageError), "a manifest no config can pin, version %q", version)
	}
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV2)
	for _, build := range []func() (*Verifier, error){
		func() (*Verifier, error) { return newEmbeddedVerifier(inputs) },
		func() (*Verifier, error) { return NewVerifier(ConfigSigningKeys{Keys: keys}, Policy{}) },
		func() (*Verifier, error) {
			return NewVerifier(nil, Policy{Artifacts: EndorsedArtifacts{FreshnessKeys: keys}})
		},
	} {
		v, err := build()
		require.NoError(t, err)
		_, err = v.VerifyV3(raw, nonce, Pin{Project: "org/project"})
		require.ErrorContains(t, err, "configured trust requires")
	}
}

func TestEndorsedConfigWithEmbeddedArtifactsRetainsFreshnessAndAuthority(t *testing.T) {
	inputs := embeddedInputs(t)
	f := sigstoretest.New(t)
	at := f.Now.Add(-time.Minute)
	s, err := configendorsement.NewStatement(inputs.Config.Name, inputs.Config.Bytes)
	require.NoError(t, err)
	timestampInput, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, timestampInput, at))
	require.NoError(t, err)
	bundle := sigstoretest.MarshalBundle(t, f.Bundle(t, payload))
	v, err := NewVerifier(ConfigSigningKeys{Keys: []crypto.PublicKey{f.Key.Public()}}, Policy{Artifacts: EmbeddedArtifacts{Runtime: inputs.Runtime, Platform: inputs.Platform}})
	require.NoError(t, err)
	v.configVerifier, err = endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	pins := endorsement.ConfigPolicy{Identity: "/org/project", Now: f.Now, MaxAge: v.freshnessMaxAge}
	approved, err := v.configVerifier.Verify(inputs.Config.Bytes, bundle, pins)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"endorsement_ref": approved.Reference, "config_base64": base64.StdEncoding.EncodeToString(inputs.Config.Bytes), "sigstore_bundle": jsontext.Value(bundle)})
	require.NoError(t, err)
	_, _, doc := embeddedDocument(t, collateral.FormatV3, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV1Format, Data: data})
	refs, err := v.configReferences(doc, "org/project", f.Now)
	require.NoError(t, err)
	require.Equal(t, SourceEndorsement, refs.config.Source)
	require.Equal(t, SourceEmbedded, refs.artifact.Source)
	require.Equal(t, at, refs.config.ApprovalTime)
	require.Equal(t, at.Add(v.freshnessMaxAge), refs.freshnessExpiresAt)
	rejected := fmt.Errorf("config is not authorized")
	v.configAuthorizer = func(collateral.ConfigEndorsement) error { return rejected }
	_, err = v.configReferences(doc, "", f.Now)
	require.ErrorIs(t, err, rejected, "a valid endorsement must not bypass caller policy")
	v.configAuthorizer = nil
	_, err = v.configReferences(doc, "org/project", refs.freshnessExpiresAt.Add(time.Second))
	require.ErrorContains(t, err, "too old")

	other := sigstoretest.New(t)
	v.configVerifier, err = endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{other.Key.Public()})
	require.NoError(t, err)
	_, err = v.configReferences(doc, "org/project", f.Now)
	require.ErrorContains(t, err, "untrusted approval signing key")
}
