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

func TestConfigSelectsOneRuntimeVariant(t *testing.T) {
	inputs := embeddedInputs(t)
	var manifest runtime.Manifest
	require.NoError(t, json.Unmarshal(inputs.Runtime, &manifest))
	cpu := manifest.Measurements
	gpu := &runtime.VariantMeasurements{
		SNPLaunch: &runtime.SNPLaunch{Measurement: strings.Repeat("ef", runtime.MeasurementSize)},
		TDXLaunch: &runtime.TDXLaunch{MRTD: strings.Repeat("12", runtime.MeasurementSize),
			RTMR0: cpu.TDXLaunch.RTMR0, RTMR1: cpu.TDXLaunch.RTMR1, RTMR2: cpu.TDXLaunch.RTMR2, RTMR3: cpu.TDXLaunch.RTMR3},
	}
	manifest.Measurements = &runtime.Measurements{FormatVersion: runtime.VariantFormatVersion,
		Variants: map[string]*runtime.VariantMeasurements{"cpu": {SNPLaunch: cpu.SNPLaunch, TDXLaunch: cpu.TDXLaunch}, "gpu": gpu}}
	var err error
	inputs.Runtime, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, _, doc := embeddedDocument(t, collateral.FormatV3)
	for suffix, want := range map[string]*runtime.VariantMeasurements{"": manifest.Measurements.Variants["cpu"], "+gpu": gpu} {
		inputs.Config.Bytes = []byte(fmt.Sprintf("cvm-version: 0.15.0%s@sha256:%x\n", suffix, sha256.Sum256(inputs.Runtime)))
		v, err := NewVerifier(WithEmbeddedReferences(inputs))
		require.NoError(t, err)
		refs, err := v.configReferences(doc, "", time.Now())
		require.NoError(t, err)
		values := refs.quote.(quote.ConfigReferenceValues)
		require.Equal(t, sha256.Sum256(inputs.Config.Bytes), values.Hash)
		require.Equal(t, want.SNPLaunch, values.Runtime.SNPLaunch)
		require.Equal(t, want.TDXLaunch, values.Runtime.TDXLaunch)
		require.Equal(t, "v0.15.0", refs.artifact.Tag)
	}
}

func embeddedInputs(t *testing.T) EmbeddedReferences {
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
	return EmbeddedReferences{
		Config:  &EmbeddedConfig{Name: embeddedConfigName, Bytes: []byte(fmt.Sprintf("cvm-version: 0.15.0@sha256:%x\n", sha256.Sum256(manifest)))},
		Runtime: manifest, Platform: platform,
	}
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

func TestEmbeddedReferencesPreserveBindingsAndOwnTheirBytes(t *testing.T) {
	inputs := embeddedInputs(t)
	configHash := sha256.Sum256(inputs.Config.Bytes)
	v, err := NewVerifier(WithEmbeddedReferences(inputs))
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
	result, err := v.VerifyV3(raw, nonce, "org/project@v1")
	require.Nil(t, result)
	requireRejectedAt(t, err, LayerQuote, "embedding must never bypass hardware authentication")
	_, err = v.VerifyV3(raw, nonce, "")
	requireRejectedAt(t, err, LayerQuote, "exact local bytes can identify a workload without a registry pin")
}

func TestEmbeddedReferencesCannotOverridePins(t *testing.T) {
	inputs := embeddedInputs(t)
	v, err := NewVerifier(WithEmbeddedReferences(inputs))
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	for _, ref := range []string{"other/project", "org/project@v2", "org/project@sha256:" + strings.Repeat("00", sha256.Size)} {
		_, err := v.VerifyV3(raw, nonce, ref)
		var usage *UsageError
		require.ErrorAs(t, err, &usage, "a pin the embedded config cannot meet is the caller's mistake")
		require.ErrorContains(t, err, "does not match the caller's pins")
	}
	inputs.Runtime = append(inputs.Runtime, '\n')
	_, err = NewVerifier(WithEmbeddedReferences(inputs))
	require.ErrorAs(t, err, new(*UsageError), "a manifest the embedded config does not pin is the caller's mistake")
	require.ErrorContains(t, err, "config's digest pin")

	inputs = embeddedInputs(t)
	inputs.Config.Name = ""
	v, err = NewVerifier(WithEmbeddedReferences(inputs))
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, "org/project")
	var usage *UsageError
	require.ErrorAs(t, err, &usage)
	require.ErrorContains(t, err, "does not match the caller's pins")
	_, err = v.VerifyV3(raw, nonce, "")
	requireRejectedAt(t, err, LayerQuote)
}

func TestEmbeddedReferencesStillRequireOtherEndorsements(t *testing.T) {
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
			v, err := NewVerifier(WithEmbeddedReferences(inputs))
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
	for _, refs := range []EmbeddedReferences{{}, {Config: &EmbeddedConfig{}}, {Runtime: []byte{}}, {Runtime: []byte(`{}`)}, {Platform: []byte{}}, {Platform: []byte(`{"format":"unknown"}`)}} {
		_, err := NewVerifier(WithEmbeddedReferences(refs))
		require.Error(t, err)
	}
	for _, version := range []string{"", "0.15.0", "v0.15"} {
		var manifest runtime.Manifest
		require.NoError(t, json.Unmarshal(inputs.Runtime, &manifest))
		manifest.Version = version
		data, err := json.Marshal(manifest)
		require.NoError(t, err)
		_, err = NewVerifier(WithEmbeddedReferences(EmbeddedReferences{Runtime: data}))
		require.ErrorAs(t, err, new(*UsageError), "a manifest no config can pin, version %q", version)
	}
	for _, options := range [][]Option{
		{WithEmbeddedReferences(inputs), WithConfigSigningKeys(keys)},
		{WithConfigSigningKeys(keys), WithEmbeddedReferences(inputs)},
		{WithEmbeddedReferences(inputs), WithFreshnessSigningKeys(keys)},
		{WithFreshnessSigningKeys(keys), WithEmbeddedReferences(inputs)},
	} {
		_, err := NewVerifier(options...)
		require.Error(t, err)
	}
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV2)
	for _, option := range []Option{WithEmbeddedReferences(inputs), WithConfigSigningKeys(keys), WithFreshnessSigningKeys(keys)} {
		v, err := NewVerifier(option)
		require.NoError(t, err)
		_, err = v.VerifyV3(raw, nonce, "org/project")
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
	v, err := NewVerifier(WithEmbeddedReferences(EmbeddedReferences{Runtime: inputs.Runtime, Platform: inputs.Platform}))
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
	require.NoError(t, WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return rejected })(v))
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
