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
	"crypto"
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
	endorsements      *endorsement.Client
	configKeys        []crypto.PublicKey
	configVerifier    *endorsement.ConfigVerifier
	freshnessKeys     []crypto.PublicKey
	freshnessVerifier *endorsement.FreshnessVerifier

	// overrides is empty in a production build; the conformance build uses it
	// to carry synthetic vendor roots down to the CPU evidence layer.
	overrides overrides
}

// NewVerifier builds a Verifier from opts. Defaults use embedded production trust,
// Tinfoil's public config and artifact signing keys, and a seven-day freshness bound.
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
	publicKeys, err := endorsement.PublicSigningKeys()
	if err != nil {
		return nil, configurationError(err)
	}
	v.configVerifier, err = endorsementClient.ConfigVerifier(publicKeys)
	if err != nil {
		return nil, configurationError(err)
	}
	v.freshnessVerifier, err = endorsementClient.FreshnessVerifier(publicKeys)
	if err != nil {
		return nil, configurationError(err)
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(v); err != nil {
			return nil, configurationError(err)
		}
	}
	if v.configKeys != nil {
		v.configVerifier, err = v.endorsements.ConfigVerifier(v.configKeys)
		if err != nil {
			return nil, configurationError(err)
		}
		v.configKeys = nil
	}
	if v.freshnessKeys != nil {
		v.freshnessVerifier, err = v.endorsements.FreshnessVerifier(v.freshnessKeys)
		if err != nil {
			return nil, configurationError(err)
		}
		v.freshnessKeys = nil
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

// VerifyV3 appraises a nonce-bound v3 attestation document using its collateral
// version. repo pins the expected repository or registry project as
// org/project[@revision][@sha256:digest].
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

type referenceValues struct {
	quote              quote.ReferenceValues
	artifact           endorsement.AuthenticatedArtifact
	config             *ConfigVerification
	freshnessExpiresAt time.Time
}

// verifyV3 is VerifyV3, also reporting which layer rejected the document.
func (v *Verifier) verifyV3(docBytes, nonce []byte, repo string) (*Verification, layer, error) {
	if v == nil || v.now == nil || v.endorsements == nil || v.configVerifier == nil || v.freshnessVerifier == nil {
		return nil, layerNone, &errs.ConfigurationError{Err: fmt.Errorf("verifier must be built with NewVerifier")}
	}
	name, revision, digest, err := endorsement.ParseReference(repo)
	if err != nil {
		return nil, layerProvenance, &errs.ConfigurationError{Err: err}
	}
	doc, err := document.Parse(docBytes, nonce)
	if err != nil {
		return nil, layerEnvelope, err
	}

	// All reference values are appraised against the same instant.
	now := v.now()

	var refs *referenceValues
	switch doc.CollateralFormat() {
	case collateral.FormatV3:
		if v.ignoreFreshness {
			return nil, layerProvenance, configurationError(fmt.Errorf("config verification requires config, platform, and runtime freshness"))
		}
		policy := endorsement.ConfigPolicy{
			Identity: "/" + name, Revision: revision, Digest: digest,
			Now: now, MaxAge: v.freshnessMaxAge,
		}
		if err := policy.ValidatePins(); err != nil {
			return nil, layerProvenance, configurationError(err)
		}
		refs, err = v.configReferences(doc, policy)
	case collateral.FormatV2:
		refs, err = v.codeReferences(doc, repo, now)
	default:
		return nil, layerProvenance, errs.WrapAttestation(fmt.Errorf("unsupported collateral format %q", doc.CollateralFormat()))
	}
	if err != nil {
		return nil, layerProvenance, errs.WrapAttestation(fmt.Errorf("reference values: %w", err))
	}

	authenticated, err := quote.Authenticate(doc.CPUEvidence(), doc.CPUEndorsements(), v.quoteOptions(now))
	if err != nil {
		return nil, layerQuote, err
	}
	assembled, err := quote.Assemble(doc, refs.quote, v.pinnedRegisters, authenticated)
	if err != nil {
		return nil, layerPolicy, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, layerPolicy, err
	}

	return &Verification{
		ConfigRepo:         refs.artifact.Repo,
		CodeDigest:         refs.artifact.Digest,
		CodeTag:            refs.artifact.Tag,
		CodeMeasurement:    assembled.CodeMeasurement,
		Config:             refs.config,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: refs.freshnessExpiresAt,
		Metadata: VerificationMetadata{
			Verifier:   SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()},
			VerifiedAt: now.UTC(),
		},
	}, layerNone, nil
}

func (v *Verifier) codeReferences(doc *document.Document, repo string, appraisalTime time.Time) (*referenceValues, error) {
	codeRef, err := doc.SigstoreCode()
	if err != nil {
		return nil, err
	}
	code, err := v.endorsements.AuthenticateCode(codeRef.Bundle, repo, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, fmt.Errorf("verifying code measurement: %w", err)
	}
	platformRef, err := doc.SigstorePlatform()
	if err != nil {
		return nil, err
	}
	endorsements, err := v.endorsements.AuthenticatePlatformEndorsements(platformRef.Bundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	refs := &referenceValues{
		quote: quote.LegacyReferenceValues{
			Endorsements: endorsements.Artifact, Code: code.Measurement, Shape: code.Shape,
		},
		artifact: code.AuthenticatedArtifact,
	}
	if v.ignoreFreshness {
		return refs, nil
	}

	codeWitnessedAt, err := v.authenticateFreshness(doc, collateral.FreshnessIDCode, &code.AuthenticatedArtifact, appraisalTime)
	if err != nil {
		return nil, fmt.Errorf("verifying code freshness: %w", err)
	}
	platformWitnessedAt, err := v.authenticateFreshness(doc, collateral.FreshnessIDPlatform, &endorsements.AuthenticatedArtifact, appraisalTime)
	if err != nil {
		return nil, fmt.Errorf("verifying platform freshness: %w", err)
	}
	refs.freshnessExpiresAt = freshnessExpiration(v.freshnessMaxAge, codeWitnessedAt, platformWitnessedAt)
	return refs, nil
}

func (v *Verifier) authenticateFreshness(doc *document.Document, id string, artifact *endorsement.AuthenticatedArtifact, now time.Time) (time.Time, error) {
	freshness, err := doc.Freshness(id)
	if err != nil {
		return time.Time{}, err
	}
	if freshness.Format != collateral.SigstoreFreshnessV1Format {
		return time.Time{}, fmt.Errorf("legacy verification requires freshness collateral format %q", collateral.SigstoreFreshnessV1Format)
	}
	return v.endorsements.AuthenticateFreshness(freshness.Bundle, artifact, now, v.freshnessMaxAge)
}

// freshnessExpiration uses authenticated witness times, never local verification time.
func freshnessExpiration(maxAge time.Duration, first time.Time, rest ...time.Time) time.Time {
	for _, issuedAt := range rest {
		if issuedAt.Before(first) {
			first = issuedAt
		}
	}
	return first.Add(maxAge)
}
