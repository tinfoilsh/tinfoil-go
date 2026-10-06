// Package verify appraises Tinfoil attestation documents.
//
// It is the functional core of the SDK: given a document, the nonce the caller
// bound it to, and the repository the caller trusts, a Verifier decides what
// the document proves. It opens no connections and keeps no state between
// calls, so fetching documents, caching a verification and enforcing its
// expiry all belong to the caller — see package enclave for an implementation
// that does those things.
//
// This package also re-exports the SDK's error categories, which are defined
// in internal/errs so the lower-level verification packages can classify
// their errors without importing this one, which imports them in turn.
package verify

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Verifier appraises attestation documents against a fixed policy.
//
// A Verifier is immutable once built and safe for concurrent use. It performs
// no I/O: the document arrives as an argument, and every trust anchor it needs
// is embedded in this module or carried by the document itself. It holds no
// cache, so it never decides that an earlier answer is still good enough —
// that judgement belongs to whatever fetches documents.
//
// It does read the clock. VerifyV3 samples it once and judges the freshness
// witnesses against that instant. The CPU evidence layer reads the clock
// separately for vendor certificate and CRL validity windows, because a
// production build has no way to pass an instant down to it (see
// overrides.go); only the conformance build threads one through. Unless
// freshness is explicitly ignored, the same document is accepted today and
// rejected once its witnesses go stale.
type Verifier struct {
	pinnedRegisters *measurement.Measurement
	freshnessMaxAge time.Duration
	ignoreFreshness bool
	now             func() time.Time

	// endorsements authenticates reference values against its own copy of the
	// trusted root. NewVerifier builds one from the embedded root; only the
	// conformance build can replace it.
	endorsements *endorsement.Client

	// overrides is empty in a production build; the conformance build uses it
	// to carry synthetic vendor roots down to the CPU evidence layer.
	overrides overrides
}

// NewVerifier builds a Verifier from opts. With no options it appraises against
// the release measurements alone, with the seven-day freshness bound.
func NewVerifier(opts ...Option) (*Verifier, error) {
	// Build default endorsement.Client with embedded roots
	endorsementClient, err := endorsement.NewDefaultClient()
	if err != nil {
		return nil, configurationError(err)
	}
	v := &Verifier{
		freshnessMaxAge: endorsement.MaxFreshnessAge,
		now:             time.Now,
		endorsements:    endorsementClient,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(v); err != nil {
			return nil, configurationError(err)
		}
	}
	return v, nil
}

// ParseReference validates owner/name[@tag][@sha256:digest] and returns its parts.
func ParseReference(ref string) (repo, tag, digest string, err error) {
	return endorsement.ParseReference(ref)
}

// FreshnessMaxAge reports the configured witness age bound.
func (v *Verifier) FreshnessMaxAge() time.Duration { return v.freshnessMaxAge }

// PinnedRegisters returns a copy of the configured register pins, or nil.
func (v *Verifier) PinnedRegisters() *measurement.Measurement {
	return cloneMeasurement(v.pinnedRegisters)
}

// VerifyV3 appraises a nonce-bound v3 attestation document. repo is the
// trusted owner/name[@tag][@sha256:digest] the code provenance must match.
//
// The caller owns both expectations that cannot come from the document: the
// nonce it generated, and repo. On success it must bind its traffic to the
// returned keys and stop authorizing new requests at FreshnessExpiresAt.
func (v *Verifier) VerifyV3(docBytes, nonce []byte, repo string) (*Verification, error) {
	verified, _, err := v.verifyV3(docBytes, nonce, repo)
	return verified, err
}

// layer names the verification step that rejected a document. It travels
// beside the error rather than inside it, so it changes nothing about how
// errors are classified or displayed; only the conformance build reads it.
type layer string

const (
	layerNone       layer = ""
	layerEnvelope   layer = "envelope"
	layerProvenance layer = "provenance"
	layerQuote      layer = "quote"
	layerPolicy     layer = "policy"
)

// verifyV3 is VerifyV3, also reporting which layer rejected the document.
func (v *Verifier) verifyV3(docBytes, nonce []byte, repo string) (*Verification, layer, error) {
	if v == nil || v.now == nil || v.endorsements == nil {
		return nil, layerNone, &errs.ConfigurationError{Err: fmt.Errorf("verifier must be built with NewVerifier")}
	}
	configRepo, _, _, err := endorsement.ParseReference(repo)
	if err != nil {
		return nil, layerProvenance, &errs.ConfigurationError{Err: err}
	}
	doc, err := document.Parse(docBytes, nonce)
	if err != nil {
		return nil, layerEnvelope, err
	}

	// Sampled once, so freshness appraisal and the CPU evidence windows judge
	// this document against the same instant.
	now := v.now()

	code, endorsements, freshnessExpiresAt, err := v.authenticateReferenceValues(doc, repo, now)
	if err != nil {
		return nil, layerProvenance, errs.WrapAttestation(fmt.Errorf("reference values: %w", err))
	}

	authenticated, err := quote.Authenticate(doc.CPUEvidence(), doc.CPUEndorsements(), v.quoteOptions(now))
	if err != nil {
		return nil, layerQuote, err
	}
	assembled, err := quote.Assemble(doc, quote.ReferenceValues{
		Endorsements: endorsements.Artifact, Code: code.Measurement, Shape: code.Shape,
	}, v.pinnedRegisters, authenticated)
	if err != nil {
		return nil, layerPolicy, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, layerPolicy, err
	}

	return &Verification{
		ConfigRepo:         configRepo,
		CodeDigest:         code.Digest,
		CodeTag:            code.Tag,
		CodeMeasurement:    code.Measurement,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: freshnessExpiresAt,
		Metadata: VerificationMetadata{
			Verifier:   SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()},
			VerifiedAt: now.UTC(),
		},
	}, layerNone, nil
}

func (v *Verifier) authenticateReferenceValues(doc *document.Document, repo string, appraisalTime time.Time) (*endorsement.Code, *endorsement.PlatformEndorsements, time.Time, error) {
	codeRef, err := doc.SigstoreCode()
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	code, err := v.endorsements.AuthenticateCode(codeRef.Bundle, repo, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code measurement: %w", err)
	}
	platformRef, err := doc.SigstorePlatform()
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	endorsements, err := v.endorsements.AuthenticatePlatformEndorsements(platformRef.Bundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	if v.ignoreFreshness {
		return code, endorsements, time.Time{}, nil
	}

	codeFreshness, err := doc.Freshness(collateral.FreshnessIDCode)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	codeWitnessedAt, err := v.endorsements.AuthenticateFreshness(codeFreshness.Bundle, &code.AuthenticatedArtifact, appraisalTime, v.freshnessMaxAge)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code freshness: %w", err)
	}
	platformFreshness, err := doc.Freshness(collateral.FreshnessIDPlatform)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	platformWitnessedAt, err := v.endorsements.AuthenticateFreshness(platformFreshness.Bundle, &endorsements.AuthenticatedArtifact, appraisalTime, v.freshnessMaxAge)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying platform freshness: %w", err)
	}

	return code, endorsements, freshnessExpiration(codeWitnessedAt, platformWitnessedAt, v.freshnessMaxAge), nil
}

// freshnessExpiration uses authenticated witness times, never local verification time.
func freshnessExpiration(codeWitnessedAt, platformWitnessedAt time.Time, maxAge time.Duration) time.Time {
	expiresAt := codeWitnessedAt.Add(maxAge)
	platformExpiresAt := platformWitnessedAt.Add(maxAge)
	if platformExpiresAt.Before(expiresAt) {
		expiresAt = platformExpiresAt
	}
	return expiresAt
}
