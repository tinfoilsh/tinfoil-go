package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

func TestConfigTrustRequiresEndorsements(t *testing.T) {
	const ref = "org/project"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keys := []crypto.PublicKey{key.Public()}
	_, err = NewVerifier(WithFreshnessSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	_, err = NewVerifier(WithConfigSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	v, err := NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys(keys))
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, ref)
	require.ErrorIs(t, err, collateral.ErrNotFound)
}

func TestDigestEndorsementBindsQuoteAndRuntimeWithoutConfig(t *testing.T) {
	f := sigstoretest.New(t)
	inputs := embeddedInputs(t)
	config := inputs.Config.Bytes
	s, err := configendorsement.NewDeploymentStatement(embeddedConfigName, configendorsement.PublicRegistryID, config)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	reference, err := configendorsement.EndorsementReference(payload)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{
		"endorsement_ref": reference,
		"sigstore_bundle": jsontext.Value(sigstoretest.MarshalBundle(t, f.Bundle(t, payload))),
	})
	require.NoError(t, err)
	raw, nonce, doc := embeddedDocument(t, collateral.FormatV3, collateral.Entry{
		ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV2Format, Data: data,
	})
	inputs.Config = nil
	v, err := NewVerifier(WithEmbeddedReferences(inputs), WithConfigSigningKeys([]crypto.PublicKey{f.Key.Public()}))
	require.NoError(t, err)
	v.configVerifier, err = endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	refs, err := v.configReferences(doc, "org/project@v1", f.Now)
	require.NoError(t, err)
	values := refs.quote.(quote.ConfigReferenceValues)
	require.Equal(t, sha256.Sum256(config), values.Hash)
	require.Equal(t, strings.Repeat("ab", 48), values.Runtime.SNPLaunch.Measurement)
	require.Equal(t, SourceEndorsement, refs.config.Source)
	require.Equal(t, reference, refs.config.Reference)
	require.Equal(t, f.Now.Add(v.freshnessMaxAge), refs.freshnessExpiresAt)
	_, err = v.VerifyV3At(raw, nonce, "org/project@v1", f.Now)
	requireRejectedAt(t, err, LayerQuote)
	_, err = v.configReferences(doc, "org/other", f.Now)
	require.ErrorContains(t, err, "pinned identity")
	altered := bytes.Clone(config)
	altered[0] ^= 1
	for _, attached := range [][]byte{config, altered, append(bytes.Clone(config), '\n')} {
		data, err := json.Marshal(map[string]any{
			"endorsement_ref": reference, "config_base64": base64.StdEncoding.EncodeToString(attached),
			"sigstore_bundle": jsontext.Value(sigstoretest.MarshalBundle(t, f.Bundle(t, payload))),
		})
		require.NoError(t, err)
		_, _, withBytes := embeddedDocument(t, collateral.FormatV3, collateral.Entry{
			ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV2Format, Data: data,
		})
		got, err := v.configReferences(withBytes, "org/project@v1", f.Now)
		if !bytes.Equal(attached, config) {
			require.ErrorContains(t, err, "config bytes do not match")
		} else {
			require.NoError(t, err)
			require.Equal(t, refs, got)
		}
	}
	inputs.Runtime = append(inputs.Runtime, '\n')
	v, err = NewVerifier(WithEmbeddedReferences(inputs), WithConfigSigningKeys([]crypto.PublicKey{f.Key.Public()}))
	require.NoError(t, err)
	v.configVerifier, err = endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	_, err = v.configReferences(doc, "org/project@v1", f.Now)
	require.ErrorContains(t, err, "digest pin")
}

const privateRegistryID = configendorsement.RegistryIDPrefix + "9c4a7f21e0b836d56a13c8fe42d907ab"

func TestScopedConfigRetainsFreshnessAfterCertificateExpiry(t *testing.T) {
	f := sigstoretest.New(t)
	approvalTime := f.Now.Add(configendorsement.CertificateClockSkew / 2)
	rootKey := f.Key
	leaf := sigstoretest.New(t).Key
	certificate := f.ScopeCertificate(t, leaf.Public(), privateRegistryID, f.Now)
	f.Key = leaf
	inputs := embeddedInputs(t)
	s, err := configendorsement.NewDeploymentStatement(embeddedConfigName, privateRegistryID, inputs.Config.Bytes)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, approvalTime))
	require.NoError(t, err)
	reference, err := configendorsement.EndorsementReference(payload)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"endorsement_ref": reference, "issuer_certificate_der": certificate.Issuer,
		"sigstore_bundle": jsontext.Value(sigstoretest.MarshalBundle(t, f.CertifiedBundle(t, payload, certificate, f.Now)))})
	require.NoError(t, err)
	_, _, doc := embeddedDocument(t, collateral.FormatV3, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV2Format, Data: data})
	inputs.Config = nil
	for _, test := range []struct {
		name     string
		options  []Option
		accepted bool
	}{
		{"default", nil, false},
		{"exclusive", []Option{WithConfigRegistryIDs(privateRegistryID)}, true},
		{"additive", []Option{WithAdditionalConfigRegistryIDs(privateRegistryID)}, true},
		{"other registry", []Option{WithConfigRegistryIDs(configendorsement.PublicRegistryID)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, err := NewVerifier(append(test.options, WithEmbeddedReferences(inputs))...)
			require.NoError(t, err)
			v.configVerifier, err = endorsement.NewRegistryVerifier(&f.Trust, []crypto.PublicKey{rootKey.Public()})
			require.NoError(t, err)
			refs, err := v.configReferences(doc, "org/project@v1", f.Now.Add(24*time.Hour))
			if !test.accepted {
				require.ErrorContains(t, err, "registry ID is not accepted")
				return
			}
			require.NoError(t, err)
			require.Equal(t, privateRegistryID, refs.config.RegistryID)
			require.Equal(t, f.Now, refs.config.SignatureTime)
			require.Equal(t, approvalTime, refs.config.ApprovalTime)
			require.Equal(t, approvalTime.Add(v.freshnessMaxAge), refs.freshnessExpiresAt)
			_, err = v.configReferences(doc, "org/project@v1", f.Now.Add(v.freshnessMaxAge+time.Second))
			require.NoError(t, err, "signature age does not shorten approval freshness")
			_, err = v.configReferences(doc, "org/project@v1", refs.freshnessExpiresAt.Add(time.Second))
			require.ErrorContains(t, err, "approval is too old")
			_, err = v.configReferences(doc, "org/other", f.Now)
			require.ErrorContains(t, err, "pinned identity")
		})
	}
}

func TestConfigRegistryIDOptionsRejectAmbiguousTrust(t *testing.T) {
	f := sigstoretest.New(t)
	for _, test := range []struct {
		options []Option
		want    string
	}{
		{[]Option{WithConfigRegistryIDs()}, "must not be empty"},
		{[]Option{WithAdditionalConfigRegistryIDs()}, "must not be empty"},
		{[]Option{WithConfigRegistryIDs("")}, "canonical registry URI"},
		{[]Option{WithConfigRegistryIDs(privateRegistryID, privateRegistryID)}, "duplicate config registry ID"},
		{[]Option{WithConfigRegistryIDs(privateRegistryID), WithAdditionalConfigRegistryIDs(privateRegistryID)}, "must be supplied once"},
		{[]Option{WithAdditionalConfigRegistryIDs(privateRegistryID), WithConfigRegistryIDs(privateRegistryID)}, "must be supplied once"},
		{[]Option{WithConfigRegistryIDs(privateRegistryID), WithConfigSigningKeys([]crypto.PublicKey{f.Key.Public()})}, "requires Tinfoil registry root"},
		{[]Option{WithConfigRegistryIDs(privateRegistryID), WithEmbeddedReferences(embeddedInputs(t))}, "require endorsement verification"},
	} {
		_, err := NewVerifier(test.options...)
		require.ErrorContains(t, err, test.want)
	}
	registryIDs := []string{privateRegistryID}
	option := WithConfigRegistryIDs(registryIDs...)
	registryIDs[0] = configendorsement.PublicRegistryID
	v, err := NewVerifier(option)
	require.NoError(t, err)
	pins, err := v.referencePins("")
	require.NoError(t, err)
	require.Equal(t, []string{privateRegistryID}, pins.RegistryIDs)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV2}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, "org/project")
	require.ErrorContains(t, err, "configured trust requires")
}

func TestCollateralVersionSelectsVerification(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	for _, tc := range []struct{ format, want string }{
		{"", collateral.SigstoreCodeV1Format},
		{collateral.FormatV2, collateral.SigstoreCodeV1Format},
		{collateral.FormatV3, collateral.ConfigID},
	} {
		t.Run(tc.format, func(t *testing.T) {
			raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: tc.format}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
			require.NoError(t, err)
			_, err = v.VerifyV3(raw, nonce, "org/project")
			require.ErrorContains(t, err, tc.want)
			requireRejectedAt(t, err, LayerProvenance)
		})
	}
}

func TestConfigReferencePins(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	const repo = "org/project"
	digest := strings.Repeat("ab", sha256.Size)
	for _, ref := range []string{"", repo, repo + "@v1", repo + "@sha256:" + digest, repo + "@v1@sha256:" + digest} {
		_, err := v.VerifyV3(raw, nonce, ref)
		require.ErrorIs(t, err, collateral.ErrNotFound, "valid pins must reach endorsement verification")
	}
	for _, ref := range []string{"/org/project", "Org/project", "org/project_name", "org/project@v1/path", "org/project@sha256:bad", "org/project@v1@v2"} {
		_, err := v.VerifyV3(raw, nonce, ref)
		var usage *UsageError
		require.ErrorAs(t, err, &usage, ref)
	}
}

func TestConfigBoundFreshnessExpirationIncludesEveryApproval(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	for _, times := range [][3]time.Time{{older, now, now}, {now, older, now}, {now, now, older}} {
		require.Equal(t, older.Add(time.Hour), freshnessExpiration(time.Hour, times[0], times[1], times[2]))
	}
}

func TestConfiguredKeysPreserveProofVerification(t *testing.T) {
	f := sigstoretest.New(t)
	configKey := f.Key.Public()
	trust, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, f.Trust.TimestampingAuthorities(), f.Trust.RekorLogs())
	require.NoError(t, err)
	rootJSON, err := trust.MarshalJSON()
	require.NoError(t, err)
	client, err := endorsement.NewClientFromJSON(rootJSON)
	require.NoError(t, err)
	config := []byte("cvm-version: 0.15.0@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	s, err := configendorsement.NewStatement("/org/project/v1", config)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	configBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, payload))
	ref, err := configendorsement.EndorsementReference(payload)
	require.NoError(t, err)
	configData, err := json.Marshal(map[string]any{"endorsement_ref": ref, "config_base64": base64.StdEncoding.EncodeToString(config), "sigstore_bundle": jsontext.Value(configBundle)})
	require.NoError(t, err)

	f.Key = sigstoretest.New(t).Key
	artifact := freshness.Artifact{Kind: freshness.KindRuntime, Repo: freshness.RuntimeRepo, Tag: "v0.15.0", Name: freshness.RuntimeName("v0.15.0"), Digest: strings.Repeat("ab", sha256.Size)}
	approval, err := freshness.NewStatement(artifact)
	require.NoError(t, err)
	input, err = approval.TimestampInput()
	require.NoError(t, err)
	payload, err = approval.Complete(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	freshnessData, err := json.Marshal(map[string]any{"sigstore_bundle": jsontext.Value(sigstoretest.MarshalBundle(t, f.Bundle(t, payload)))})
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3, Collateral: []collateral.Entry{
		{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV1Format, Data: configData},
		{ID: collateral.FreshnessIDRuntime, Role: collateral.RoleReferenceValues, Format: collateral.ArtifactFreshnessV1Format, Data: freshnessData},
	}}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	doc, err := document.Parse(raw, nonce)
	require.NoError(t, err)
	for _, expired := range []bool{false, true} {
		v, err := NewVerifier(WithConfigSigningKeys([]crypto.PublicKey{configKey}), WithFreshnessSigningKeys([]crypto.PublicKey{f.Key.Public()}), func(v *Verifier) error {
			v.endorsements = client
			return nil
		})
		require.NoError(t, err)
		now := f.Now
		if expired {
			now = now.Add(endorsement.DefaultMaxAge + time.Second)
		}
		_, err = v.configReferences(doc, "org/project@v1", now)
		if expired {
			require.ErrorContains(t, err, "too old")
		} else {
			require.ErrorIs(t, err, collateral.ErrNotFound, "valid config must proceed to required runtime provenance")
			require.ErrorContains(t, err, collateral.RuntimeID)
		}
		authenticated := &endorsement.AuthenticatedArtifact{Repo: artifact.Repo, Tag: artifact.Tag, SubjectName: artifact.Name, Digest: artifact.Digest}
		at, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDRuntime, artifact.Kind, authenticated, now)
		if expired {
			require.ErrorContains(t, err, "too old")
		} else {
			require.NoError(t, err)
			require.Equal(t, f.Now, at)
		}
		_, err = v.authenticateArtifactFreshness(doc, collateral.FreshnessIDPlatform, freshness.KindPlatform, authenticated, now)
		require.ErrorIs(t, err, collateral.ErrNotFound)
		authenticated.Digest = strings.Repeat("cd", sha256.Size)
		_, err = v.authenticateArtifactFreshness(doc, collateral.FreshnessIDRuntime, artifact.Kind, authenticated, now)
		require.ErrorContains(t, err, "does not match")
		_, err = v.configReferences(doc, "org/other", now)
		require.ErrorContains(t, err, "pinned identity")
	}
}
