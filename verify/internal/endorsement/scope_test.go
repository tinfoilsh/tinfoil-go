package endorsement_test

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/scope"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestScopedConfigApprovalAndPins(t *testing.T) {
	f := sigstoretest.New(t)
	rootKey := f.Key
	leaf := sigstoretest.New(t).Key
	identity := scope.Identity{
		OwnerKind: scope.Organization, OwnerID: "c5cbb595-6271-45a0-a851-65c67173ee8a",
		ScopeID: "36c405e9-30df-4fe7-85d5-c1a509484541", Namespace: "tinfoil",
	}
	material := f.Scope(t, leaf.Public(), identity)
	f.Key = leaf
	config := []byte("cvm-version: 0.15.0@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	s, err := configendorsement.NewDeploymentStatement(testName, config)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	bundle := sigstoretest.MarshalBundle(t, f.Bundle(t, payload))
	v, err := endorsement.NewRegistryVerifier(&f.Trust, []crypto.PublicKey{rootKey.Public()}, []crypto.PublicKey{rootKey.Public()})
	require.NoError(t, err)
	policy := endorsement.ConfigPolicy{Now: f.Now}
	verified, err := v.VerifyScoped(nil, bundle, material, policy)
	require.NoError(t, err)
	require.Equal(t, identity, verified.Scope)
	require.Equal(t, f.Now.Add(scope.Validity), verified.ScopeExpiresAt)
	require.Equal(t, testName, verified.Name)
	policy.Identity, policy.Revision, policy.Digest = testIdentity, "v0.0.155", verified.Digest
	policy.Scope = scope.Pins{OwnerKind: identity.OwnerKind, OwnerID: identity.OwnerID, ScopeID: identity.ScopeID, Namespace: identity.Namespace, SigningKeyHint: verified.SigningKeyHint}
	_, err = v.VerifyScoped(nil, bundle, material, policy)
	require.NoError(t, err)
	untrusted, err := endorsement.NewRegistryVerifier(&f.Trust, []crypto.PublicKey{rootKey.Public()}, []crypto.PublicKey{leaf.Public()})
	require.NoError(t, err)
	_, err = untrusted.VerifyScoped(nil, bundle, material, policy)
	require.ErrorContains(t, err, "untrusted registry root")
	for name, mutate := range map[string]func(*scope.Pins){
		"owner kind": func(p *scope.Pins) { p.OwnerKind = scope.User },
		"owner":      func(p *scope.Pins) { p.OwnerID = identity.ScopeID },
		"scope":      func(p *scope.Pins) { p.ScopeID = identity.OwnerID },
		"namespace":  func(p *scope.Pins) { p.Namespace = "other" },
		"key":        func(p *scope.Pins) { p.SigningKeyHint, _ = configendorsement.KeyHint(rootKey.Public()) },
	} {
		t.Run(name, func(t *testing.T) {
			p := policy
			mutate(&p.Scope)
			_, err := v.VerifyScoped(nil, bundle, material, p)
			require.ErrorContains(t, err, "does not match the caller's pins")
		})
	}
	_, err = v.Verify(nil, bundle, policy)
	require.ErrorContains(t, err, "untrusted approval signing key")

	f.Key = rootKey
	other := identity
	other.Namespace = "other"
	wrongNamespace := f.Scope(t, leaf.Public(), other)
	otherKey := f.Scope(t, sigstoretest.New(t).Key.Public(), identity)
	for name, bad := range map[string]collateral.ScopeCertificate{"namespace": wrongNamespace, "key": otherKey} {
		t.Run(name+" certificate", func(t *testing.T) {
			_, err := v.VerifyScoped(nil, bundle, bad, policy)
			require.Error(t, err)
		})
	}
	for name, mutate := range map[string]func(*protobundle.Bundle){
		"missing log":                       func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries = nil },
		"substituted certificate signature": func(b *protobundle.Bundle) { b.GetMessageSignature().Signature[0] ^= 1 },
		"untrusted log checkpoint": func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionProof.Checkpoint.Envelope += "invalid"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var b protobundle.Bundle
			require.NoError(t, protojson.Unmarshal(material.Bundle, &b))
			mutate(&b)
			bad := material
			bad.Bundle = sigstoretest.MarshalBundle(t, &b)
			_, err := v.VerifyScoped(nil, bundle, bad, policy)
			require.Error(t, err)
		})
	}
	issuer, err := x509.ParseCertificate(material.Issuer)
	require.NoError(t, err)
	laterDER, err := scope.Issue(issuer, rootKey, leaf.Public(), identity, f.Now.Add(scope.ClockSkew))
	require.NoError(t, err)
	laterCert, err := x509.ParseCertificate(laterDER)
	require.NoError(t, err)
	laterMaterial := collateral.ScopeCertificate{Certificate: laterDER, Issuer: material.Issuer, Bundle: sigstoretest.MarshalBundle(t, f.CertificateBundle(t, laterCert))}
	f.Key = leaf
	oldPayload, err := s.Complete(f.Timestamp(t, input, f.Now.Add(-time.Second)))
	require.NoError(t, err)
	_, err = v.VerifyScoped(nil, sigstoretest.MarshalBundle(t, f.Bundle(t, oldPayload)), laterMaterial, policy)
	require.ErrorContains(t, err, "outside scope authorization")

	var parsed configendorsement.Statement
	require.NoError(t, json.Unmarshal(payload, &parsed))
	parsed.Predicate.Runtime = nil
	parsed.PredicateType = configendorsement.PredicateType
	oldInput, err := parsed.TimestampInput()
	require.NoError(t, err)
	oldPayload, err = parsed.Complete(f.Timestamp(t, oldInput, f.Now))
	require.NoError(t, err)
	_, err = v.VerifyScoped(nil, sigstoretest.MarshalBundle(t, f.Bundle(t, oldPayload)), material, policy)
	require.ErrorContains(t, err, "requires a v2")
	cert, err := x509.ParseCertificate(material.Certificate)
	require.NoError(t, err)
	policy.Now = cert.NotAfter.Add(time.Second)
	_, err = v.VerifyScoped(nil, bundle, material, policy)
	require.ErrorContains(t, err, "expired")
}
