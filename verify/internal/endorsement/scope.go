package endorsement

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/tinfoilsh/tinfoil-go/endorsement/scope"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

type ScopeVerifier struct {
	certificates *scope.Verifier
	issuance     *endorsementVerifier
}

type ScopeVerified struct {
	scope.Identity
	PublicKey crypto.PublicKey
	ValidFrom time.Time
	ExpiresAt time.Time
}

func NewScopeVerifier(trust root.TrustedMaterial, keys []crypto.PublicKey) (*ScopeVerifier, error) {
	certificates, err := scope.NewVerifier(keys)
	if err != nil {
		return nil, err
	}
	issuance, err := newEndorsementVerifier(trust, keys)
	if err != nil {
		return nil, err
	}
	return &ScopeVerifier{certificates: certificates, issuance: issuance}, nil
}

func (v *ScopeVerifier) Verify(material collateral.ScopeCertificate, name string, now time.Time) (*ScopeVerified, error) {
	cert, identity, err := v.certificates.Verify(material.Certificate, material.Issuer, now)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(name, "/"+identity.Namespace+"/") {
		return nil, fmt.Errorf("registry certificate does not authorize config namespace")
	}
	if len(material.Bundle) == 0 || len(material.Bundle) > statement.MaxBundleSize {
		return nil, fmt.Errorf("scope issuance bundle size is outside allowed bounds")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(material.Bundle); err != nil {
		return nil, fmt.Errorf("parsing scope issuance bundle: %w", err)
	}
	message := b.GetMessageSignature()
	if b.GetMediaType() != statement.BundleType || message == nil ||
		message.GetMessageDigest().GetAlgorithm() != common.HashAlgorithm_SHA2_256 ||
		!bytes.Equal(message.GetSignature(), cert.Signature) {
		return nil, fmt.Errorf("issuance bundle must contain the certificate signature")
	}
	issuer, err := scope.ParseCertificate(material.Issuer)
	if err != nil {
		return nil, err
	}
	hint, err := statement.KeyHint(issuer.PublicKey)
	if err != nil {
		return nil, err
	}
	if b.GetVerificationMaterial().GetPublicKey().GetHint() != hint {
		return nil, fmt.Errorf("scope issuance log signer must match certificate issuer")
	}
	if err := validateLogMaterial(&b); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(cert.RawTBSCertificate)
	if _, err := v.issuance.Verify(&b, digest[:]); err != nil {
		return nil, fmt.Errorf("verifying scope issuance: %w", err)
	}
	return &ScopeVerified{Identity: identity, PublicKey: cert.PublicKey, ValidFrom: cert.NotBefore, ExpiresAt: cert.NotAfter}, nil
}
