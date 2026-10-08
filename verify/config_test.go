package verify

import (
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
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
)

func TestConfigTrustAndIgnoreFreshnessStillRequireEndorsements(t *testing.T) {
	const ref = "org/project"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keys := []crypto.PublicKey{key.Public()}
	_, err = NewVerifier(WithFreshnessSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	_, err = NewVerifier(WithConfigSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	v, err := NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys(keys), WithIgnoreFreshness())
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, ref)
	require.ErrorIs(t, err, collateral.ErrNotFound)
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
			_, rejectedAt, err := v.verifyV3(raw, nonce, "org/project")
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, layerProvenance, rejectedAt)
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
	for _, ref := range []string{repo, repo + "@v1", repo + "@sha256:" + digest, repo + "@v1@sha256:" + digest} {
		_, err := v.VerifyV3(raw, nonce, ref)
		require.ErrorIs(t, err, collateral.ErrNotFound, "valid pins must reach endorsement verification")
	}
	for _, ref := range []string{"", "/org/project", "Org/project", "org/project_name", "org/project@v1/path", "org/project@sha256:bad", "org/project@v1@v2"} {
		_, err := v.VerifyV3(raw, nonce, ref)
		var configErr *ConfigurationError
		require.ErrorAs(t, err, &configErr, ref)
	}
}

func TestConfigBoundFreshnessExpirationIncludesEveryApproval(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	for _, times := range [][3]time.Time{{older, now, now}, {now, older, now}, {now, now, older}} {
		require.Equal(t, older.Add(time.Hour), freshnessExpiration(time.Hour, times[0], times[1], times[2]))
	}
}

func TestConfiguredKeysAndIgnoredAgePreserveProofVerification(t *testing.T) {
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
	for _, ignore := range []bool{false, true} {
		v, err := NewVerifier(WithConfigSigningKeys([]crypto.PublicKey{configKey}), WithFreshnessSigningKeys([]crypto.PublicKey{f.Key.Public()}), func(v *Verifier) error {
			v.endorsements, v.ignoreFreshness = client, ignore
			return nil
		})
		require.NoError(t, err)
		now := f.Now.Add(endorsement.DefaultMaxAge + time.Second)
		_, err = v.configReferences(doc, "org/project@v1", now)
		if ignore {
			require.ErrorIs(t, err, collateral.ErrNotFound, "valid config must proceed to required runtime provenance")
			require.ErrorContains(t, err, collateral.RuntimeID)
		} else {
			require.ErrorContains(t, err, "too old")
		}
		authenticated := &endorsement.AuthenticatedArtifact{Repo: artifact.Repo, Tag: artifact.Tag, SubjectName: artifact.Name, Digest: artifact.Digest}
		at, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDRuntime, artifact.Kind, authenticated, now)
		if ignore {
			require.NoError(t, err)
			require.Equal(t, f.Now, at)
		} else {
			require.ErrorContains(t, err, "too old")
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
