package endorsement_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"google.golang.org/protobuf/proto"
)

const (
	testIdentity = "/tinfoil/model-router"
	testName     = testIdentity + "/v0.0.155"
)

var testConfig = []byte("# Approved config bytes\nname: gpt-oss-120b\n")

func TestScopedConfigCertificateAndTimestampBindings(t *testing.T) {
	f := sigstoretest.New(t)
	rootKey := f.Key
	leaf := sigstoretest.New(t).Key
	certificate := f.SigningCertificate(t, leaf.Public())
	f.Key = leaf
	config := []byte("cvm-version: 0.15.3-rc.1@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	s, err := configendorsement.NewDeploymentStatement(testName, configendorsement.PublicScope, config)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	b := f.CertifiedBundle(t, payload, certificate, f.Now)
	v, err := endorsement.NewRegistryVerifier(&f.Trust, []crypto.PublicKey{rootKey.Public()})
	require.NoError(t, err)
	policy := endorsement.ConfigPolicy{Identity: testIdentity, Now: f.Now.Add(24 * time.Hour), Scopes: []string{configendorsement.PublicScope}}
	check := func(b *protobundle.Bundle, issuer []byte, policy endorsement.ConfigPolicy) error {
		_, err := v.VerifyCertified(nil, sigstoretest.MarshalBundle(t, b), issuer, policy)
		return err
	}
	approved, err := v.VerifyCertified(nil, sigstoretest.MarshalBundle(t, b), certificate.Issuer, policy)
	require.NoError(t, err)
	require.Equal(t, configendorsement.PublicScope, approved.Scope)
	require.Equal(t, f.Now, approved.SignatureTime)
	_, err = v.Verify(nil, sigstoretest.MarshalBundle(t, b), policy)
	require.ErrorContains(t, err, "requires an issuer certificate")
	_, _, err = configendorsement.VerifySigningCertificate(certificate.Certificate, certificate.Issuer, []crypto.PublicKey{leaf.Public()}, f.Now)
	require.ErrorContains(t, err, "untrusted registry root")
	f.Key = rootKey
	rootLeaf := f.SigningCertificate(t, rootKey.Public())
	replacement := f.SigningCertificate(t, leaf.Public())
	f.Key = leaf
	_, _, err = configendorsement.VerifySigningCertificate(rootLeaf.Certificate, rootLeaf.Issuer, []crypto.PublicKey{rootKey.Public()}, f.Now)
	require.ErrorContains(t, err, "registry root cannot serve")
	for _, test := range []struct {
		name   string
		mutate func(*protobundle.Bundle)
		want   string
	}{
		{"missing signature timestamp", func(b *protobundle.Bundle) { b.VerificationMaterial.TimestampVerificationData = nil }, "signature timestamp"},
		{"wrong signature timestamp", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps[0].SignedTimestamp = f.Timestamp(t, []byte("other signature"), f.Now)
		}, "threshold"},
		{"certificate log substitution", func(b *protobundle.Bundle) {
			b.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{Certificate: &common.X509Certificate{RawBytes: replacement.Certificate}}
		}, "verifying log entry"},
		{"raw key log substitution", func(b *protobundle.Bundle) {
			cert := b.VerificationMaterial.Content
			b.VerificationMaterial.Content = &protobundle.VerificationMaterial_PublicKey{PublicKey: &common.PublicKeyIdentifier{Hint: approved.SigningKeyHint}}
			f.LogBundle(t, b)
			b.VerificationMaterial.Content = cert
		}, "verifying log entry"},
		{"timestamp before certificate", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps[0].SignedTimestamp = f.Timestamp(t, b.GetDsseEnvelope().Signatures[0].Sig, f.Now.Add(-time.Hour))
		}, "not yet valid"},
		{"timestamp after certificate", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps[0].SignedTimestamp = f.Timestamp(t, b.GetDsseEnvelope().Signatures[0].Sig, f.Now.Add(time.Hour))
		}, "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := proto.Clone(b).(*protobundle.Bundle)
			test.mutate(copy)
			require.ErrorContains(t, check(copy, certificate.Issuer, policy), test.want)
		})
	}
	f.Key = rootKey
	otherScope := configendorsement.ScopePrefix + "9c4a7f21e0b836d56a13c8fe42d907ab"
	other := f.ScopeCertificate(t, leaf.Public(), otherScope, f.Now)
	f.Key = leaf
	relogged := proto.Clone(b).(*protobundle.Bundle)
	relogged.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{Certificate: &common.X509Certificate{RawBytes: other.Certificate}}
	f.LogBundle(t, relogged)
	require.ErrorContains(t, check(relogged, other.Issuer, policy), "does not match signed scope")
	stale, err := s.Complete(f.Timestamp(t, input, f.Now.Add(-8*24*time.Hour)))
	require.NoError(t, err)
	require.ErrorContains(t, check(f.CertifiedBundle(t, stale, certificate, f.Now), certificate.Issuer, policy), "too old")
	issuer, err := x509.ParseCertificate(certificate.Issuer)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*x509.Certificate){
		"CA":                 func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"TLS purpose":        func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"long lifetime":      func(c *x509.Certificate) { c.NotAfter = f.Now.Add(time.Hour) },
		"identity subject":   func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "customer"} },
		"extra DNS identity": func(c *x509.Certificate) { c.DNSNames = []string{"customer.example"} },
		"missing scope":      func(c *x509.Certificate) { c.URIs = nil },
		"duplicate scope":    func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) },
		"noncritical SAN": func(c *x509.Certificate) {
			for _, ext := range c.Extensions {
				if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
					ext.Critical = false
					c.ExtraExtensions = []pkix.Extension{ext}
				}
			}
		},
		"hidden SAN identity": func(c *x509.Certificate) {
			value, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(configendorsement.PublicScope)}, {Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: []byte{0x30, 0}}})
			require.NoError(t, err)
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: value}}
		},
		"unknown critical extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cert, err := x509.ParseCertificate(certificate.Certificate)
			require.NoError(t, err)
			cert.RawSubject = nil
			mutate(cert)
			der, err := x509.CreateCertificate(rand.Reader, cert, issuer, leaf.Public(), rootKey)
			require.NoError(t, err)
			_, _, err = configendorsement.VerifySigningCertificate(der, certificate.Issuer, []crypto.PublicKey{rootKey.Public()}, f.Now)
			require.Error(t, err)
		})
	}
}

type fixture struct{ *sigstoretest.Fixture }

func newFixture(t *testing.T) *fixture { return &fixture{sigstoretest.New(t)} }

func (f *fixture) policy() endorsement.ConfigPolicy {
	return endorsement.ConfigPolicy{Identity: testIdentity, Now: f.Now}
}

func (f *fixture) verifier(t *testing.T) *endorsement.ConfigVerifier {
	t.Helper()
	v, err := endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	return v
}

func (f *fixture) statement(t *testing.T, at time.Time) []byte {
	t.Helper()
	s, err := configendorsement.NewStatement(testName, testConfig)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, at))
	require.NoError(t, err)
	return payload
}

func TestVerifyConfigApproval(t *testing.T) {
	f := newFixture(t)
	payload := f.statement(t, f.Now.Add(-time.Minute))
	b := f.Bundle(t, payload)
	got, err := f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), f.policy())
	require.NoError(t, err)
	require.Equal(t, testName, got.Name)
	require.Equal(t, f.Now.Add(-time.Minute), got.ApprovalTime)
	require.Nil(t, b.GetVerificationMaterial().GetTimestampVerificationData())
	wantRef := sha256.Sum256(dsse.PAE(configendorsement.PayloadType, payload))
	require.Equal(t, "sha256:"+hex.EncodeToString(wantRef[:]), got.Reference)

	policy := f.policy()
	policy.Revision = "v0.0.155"
	policy.Digest = got.Digest
	_, err = f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), policy)
	require.NoError(t, err)
}

func TestVerifyConfigDigestAndRuntime(t *testing.T) {
	f := newFixture(t)
	config := []byte("cvm-version: 0.15.0@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	s, err := configendorsement.NewDeploymentStatement(testName, configendorsement.PublicScope, config)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	bundle := sigstoretest.MarshalBundle(t, f.Bundle(t, payload))
	got, err := f.verifier(t).Verify(nil, bundle, f.policy())
	require.NoError(t, err)
	digest := sha256.Sum256(config)
	require.Equal(t, hex.EncodeToString(digest[:]), got.Digest)
	require.Equal(t, testName, got.Name)
	require.Equal(t, &configendorsement.RuntimeReference{
		Repo: configendorsement.RuntimeRepo, Tag: "v0.15.0", Digest: strings.Repeat("ab", sha256.Size),
	}, got.Runtime)
	require.Equal(t, f.Now, got.ApprovalTime)
	withBytes, err := f.verifier(t).Verify(config, bundle, f.policy())
	require.NoError(t, err)
	require.Equal(t, got, withBytes)
	_, err = f.verifier(t).Verify([]byte{}, bundle, f.policy())
	require.ErrorContains(t, err, "config size is outside allowed bounds")

	for name, mutate := range map[string]func(*protobundle.Bundle){
		"signature":   func(b *protobundle.Bundle) { b.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1 },
		"missing log": func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries = nil },
		"unsigned runtime change": func(b *protobundle.Bundle) {
			b.GetDsseEnvelope().Payload = bytes.Replace(payload, []byte("v0.15.0"), []byte("v0.16.0"), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := f.Bundle(t, payload)
			mutate(b)
			_, err := f.verifier(t).Verify(nil, sigstoretest.MarshalBundle(t, b), f.policy())
			require.Error(t, err)
		})
	}
	_, err = f.verifier(t).Verify(nil, sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now))), f.policy())
	require.ErrorContains(t, err, "requires a v2")
	wrongPin := f.policy()
	wrongPin.Digest = strings.Repeat("cd", sha256.Size)
	_, err = f.verifier(t).Verify(nil, bundle, wrongPin)
	require.ErrorContains(t, err, "pinned digest")
	stale := f.policy()
	stale.Now = f.Now.Add(endorsement.DefaultMaxAge + time.Second)
	_, err = f.verifier(t).Verify(nil, bundle, stale)
	require.ErrorContains(t, err, "too old")
}

func TestDeploymentRuntimeRequiresApprovalAndMatchesConfig(t *testing.T) {
	f := newFixture(t)
	config := []byte("cvm-version: 0.15.0@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	s, err := configendorsement.NewDeploymentStatement(testName, configendorsement.PublicScope, config)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	response := f.Timestamp(t, input, f.Now)
	s.Predicate.Runtime.Digest = strings.Repeat("cd", sha256.Size)
	_, err = s.Complete(response)
	require.ErrorContains(t, err, "does not match endorsement core")
	s.Predicate.Freshness = &configendorsement.Freshness{RFC3161Timestamp: response}
	payload, err := json.Marshal(s)
	require.NoError(t, err)
	_, err = f.verifier(t).Verify(nil, sigstoretest.MarshalBundle(t, f.Bundle(t, payload)), f.policy())
	require.ErrorContains(t, err, "inner timestamp")

	input, err = s.TimestampInput()
	require.NoError(t, err)
	payload, err = s.Complete(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	_, err = f.verifier(t).Verify(config, sigstoretest.MarshalBundle(t, f.Bundle(t, payload)), f.policy())
	require.ErrorContains(t, err, "config runtime does not match")
}

func TestPolicyValidatePins(t *testing.T) {
	policy := endorsement.ConfigPolicy{Identity: testIdentity}
	require.NoError(t, policy.ValidatePins())
	policy.Revision = "v0.0.155"
	policy.Digest = strings.Repeat("ab", sha256.Size)
	require.NoError(t, policy.ValidatePins())
	for name, mutate := range map[string]func(*endorsement.ConfigPolicy){
		"identity": func(p *endorsement.ConfigPolicy) { p.Identity = "/tinfoil" },
		"revision": func(p *endorsement.ConfigPolicy) { p.Revision = "../v1" },
		"digest":   func(p *endorsement.ConfigPolicy) { p.Digest = strings.ToUpper(p.Digest) },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := policy
			mutate(&invalid)
			require.Error(t, invalid.ValidatePins())
		})
	}
}

func TestApprovalVerificationRequiresTSATrust(t *testing.T) {
	f := newFixture(t)
	trust, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, nil, f.Trust.RekorLogs())
	require.NoError(t, err)
	keys := []crypto.PublicKey{f.Key.Public()}
	configs, err := endorsement.NewConfigVerifier(trust, keys)
	require.NoError(t, err)
	approvals, err := endorsement.NewFreshnessVerifier(trust, keys)
	require.NoError(t, err)
	configBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	a := artifact(freshness.KindRuntime)
	approvalBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, statement(t, f.Fixture, a, f.Now)))
	policy := f.policy()
	_, err = configs.Verify(testConfig, configBundle, policy)
	require.ErrorContains(t, err, "no trusted timestamp authority")
	_, err = approvals.Verify(approvalBundle, endorsement.FreshnessPolicy{Artifact: a, Now: f.Now})
	require.ErrorContains(t, err, "no trusted timestamp authority")
}

func TestVerifyRejectsWrongPinsAndUntrustedKeys(t *testing.T) {
	f := newFixture(t)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	for _, tc := range []struct {
		name   string
		mutate func(*endorsement.ConfigPolicy)
	}{
		{"identity", func(p *endorsement.ConfigPolicy) { p.Identity = "/tinfoil/other" }},
		{"revision", func(p *endorsement.ConfigPolicy) { p.Revision = "v0.0.156" }},
		{"digest", func(p *endorsement.ConfigPolicy) { p.Digest = strings.Repeat("0", sha256.Size*2) }},
		{"missing clock", func(p *endorsement.ConfigPolicy) { p.Now = time.Time{} }},
		{"negative age", func(p *endorsement.ConfigPolicy) { p.MaxAge = -time.Second }},
		{"negative skew", func(p *endorsement.ConfigPolicy) { p.FutureSkew = -time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := f.policy()
			tc.mutate(&policy)
			_, err := f.verifier(t).Verify(testConfig, b, policy)
			require.Error(t, err)
		})
	}
	_, err := f.verifier(t).Verify(append(bytes.Clone(testConfig), '\n'), b, f.policy())
	require.ErrorContains(t, err, "config bytes")
	other := newFixture(t)
	_, err = other.verifier(t).Verify(testConfig, b, f.policy())
	require.ErrorContains(t, err, "untrusted approval signing key")
}

func TestVerifyRequiresSignedApprovalAndLogInclusion(t *testing.T) {
	f := newFixture(t)
	payload := f.statement(t, f.Now)
	for _, tc := range []struct {
		name   string
		mutate func(*protobundle.Bundle)
	}{
		{"signature", func(b *protobundle.Bundle) { b.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1 }},
		{"checkpoint", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionProof.Checkpoint.Envelope += "invalid"
		}},
		{"proof", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionProof.Hashes = [][]byte{make([]byte, sha256.Size)}
		}},
		{"missing log", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries = nil }},
		{"legacy log", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].KindVersion.Version = "0.0.1" }},
		{"integrated time", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].IntegratedTime = f.Now.Unix() }},
		{"unexpected outer timestamp", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*common.RFC3161SignedTimestamp{{SignedTimestamp: f.Timestamp(t, b.GetDsseEnvelope().GetSignatures()[0].GetSig(), f.Now)}},
			}
		}},
		{"duplicate signature", func(b *protobundle.Bundle) {
			b.GetDsseEnvelope().Signatures = append(b.GetDsseEnvelope().Signatures, b.GetDsseEnvelope().Signatures[0])
		}},
		{"unknown key", func(b *protobundle.Bundle) { b.VerificationMaterial.GetPublicKey().Hint = "untrusted" }},
		{"signing certificate", func(b *protobundle.Bundle) {
			b.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{Certificate: &common.X509Certificate{RawBytes: f.Trust.TSA.Leaf.Raw}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := f.Bundle(t, payload)
			tc.mutate(b)
			_, err := f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), f.policy())
			require.Error(t, err)
		})
	}
}

func TestInnerTimestampBindsCompleteCore(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*configendorsement.Statement)
	}{
		{"name", func(s *configendorsement.Statement) { s.Subject[0].Name = testIdentity + "/changed" }},
		{"timestamp on other input", func(s *configendorsement.Statement) {
			s.Predicate.Freshness.RFC3161Timestamp = f.Timestamp(t, []byte("other"), f.Now)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := configendorsement.ParseStatement(f.statement(t, f.Now))
			require.NoError(t, err)
			tc.mutate(s)
			payload, err := json.Marshal(s)
			require.NoError(t, err)
			b := f.Bundle(t, payload)
			_, err = f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), f.policy())
			require.ErrorContains(t, err, "inner timestamp")
		})
	}
}

func TestFreshnessUsesInnerTimeAndInclusiveBounds(t *testing.T) {
	f := newFixture(t)
	inner := f.Now.Add(-time.Minute)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, inner)))
	policy := f.policy()
	policy.Now = inner.Add(endorsement.DefaultMaxAge)
	_, err := f.verifier(t).Verify(testConfig, b, policy)
	require.NoError(t, err)
	policy.Now = policy.Now.Add(time.Nanosecond)
	_, err = f.verifier(t).Verify(testConfig, b, policy)
	require.ErrorContains(t, err, "too old")

	policy = f.policy()
	policy.Now = inner.Add(-endorsement.DefaultFutureSkew)
	_, err = f.verifier(t).Verify(testConfig, b, policy)
	require.NoError(t, err)
	policy.Now = policy.Now.Add(-time.Nanosecond)
	_, err = f.verifier(t).Verify(testConfig, b, policy)
	require.ErrorContains(t, err, "future")
}

func TestArchivedConfigRequiresAuthenticatedApproval(t *testing.T) {
	f := newFixture(t)
	inner := f.Now.Add(-time.Minute)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, inner)))
	stale := f.policy()
	stale.Now = inner.Add(endorsement.DefaultMaxAge + time.Hour)
	_, err := f.verifier(t).Verify(testConfig, b, stale)
	require.ErrorContains(t, err, "too old")

	policy := endorsement.ConfigPolicy{Identity: testIdentity, Now: inner}
	verified, err := f.verifier(t).Verify(testConfig, b, policy)
	require.NoError(t, err)
	require.True(t, verified.ApprovalTime.Equal(inner))

	_, err = f.verifier(t).Verify(append(bytes.Clone(testConfig), '\n'), b, policy)
	require.ErrorContains(t, err, "config bytes")
	_, err = newFixture(t).verifier(t).Verify(testConfig, b, policy)
	require.ErrorContains(t, err, "untrusted approval signing key")
}

func TestUntrustedInnerTSAAndWrongPolicy(t *testing.T) {
	f := newFixture(t)
	s, err := configendorsement.NewStatement(testName, testConfig)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	other := newFixture(t)
	for _, response := range [][]byte{
		other.Timestamp(t, input, f.Now),
		f.TimestampWithPolicy(t, input, f.Now, asn1.ObjectIdentifier{1, 2, 3, 4}),
	} {
		payload, err := s.Complete(response)
		require.NoError(t, err)
		_, err = f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, f.Bundle(t, payload)), f.policy())
		require.ErrorContains(t, err, "inner timestamp")
	}
}

func TestSigningKeyRotationAllowsOverlapAndRejectsRemovedKeys(t *testing.T) {
	f := newFixture(t)
	oldKey := f.Key.Public()
	oldBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f.Key = newKey
	newTrust := f.Key.Public()
	newBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	verifier, err := endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{oldKey, newTrust})
	require.NoError(t, err)
	for _, b := range [][]byte{oldBundle, newBundle} {
		_, err := verifier.Verify(testConfig, b, f.policy())
		require.NoError(t, err)
	}
	verifier, err = endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{newTrust})
	require.NoError(t, err)
	_, err = verifier.Verify(testConfig, oldBundle, f.policy())
	require.ErrorContains(t, err, "untrusted approval signing key")
	_, err = verifier.Verify(testConfig, newBundle, f.policy())
	require.NoError(t, err)
}

func TestRegistryLegacyPublicCannotSatisfyPrivateScopePolicy(t *testing.T) {
	f := newFixture(t)
	v, err := endorsement.NewRegistryVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	raw := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	policy := f.policy()
	policy.Scopes = []string{configendorsement.PublicScope}
	approved, err := v.Verify(testConfig, raw, policy)
	require.NoError(t, err)
	require.Equal(t, configendorsement.PublicScope, approved.Scope)
	_, err = v.VerifyCertified(testConfig, raw, nil, policy)
	require.ErrorContains(t, err, "requires an issuer certificate")
	policy.Scopes = []string{configendorsement.ScopePrefix + "9c4a7f21e0b836d56a13c8fe42d907ab"}
	_, err = v.Verify(testConfig, raw, policy)
	require.ErrorContains(t, err, "scope is not accepted")
}
