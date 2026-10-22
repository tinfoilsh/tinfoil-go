// Package verify appraises Tinfoil attestation documents.
//
// It is the functional core of the SDK: given a document, the nonce the caller
// bound it to, and the repository the caller trusts, a Verifier decides what
// the document proves. It opens no connections and keeps no state between
// calls, so fetching documents, caching a verification and enforcing its
// expiry all belong to the caller — see package enclave for an implementation
// that does those things.
//
// It returns two error types: a UsageError when the verifier is built or
// called with invalid inputs, and a VerificationError when the document must
// not be trusted.
package verify

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Verifier appraises attestation documents against a fixed policy.
//
// A Verifier is immutable once built and safe for concurrent use. Its built-in
// verification performs no I/O: the document arrives as an argument, and every trust anchor it needs
// is embedded in this module or carried by the document itself. It holds no
// cache, so it never decides that an earlier answer is still good enough —
// that judgement belongs to whatever fetches documents.
//
// It does read the clock. VerifyV3 samples it once and judges everything
// time-bound against that instant: the freshness witnesses and approvals, and
// the vendor certificate and CRL validity windows of the CPU evidence. The
// same instant is reported as VerifiedAt. VerifyV3At takes that instant from
// the caller instead. Unless freshness is explicitly ignored, the same
// document is accepted today and rejected once its witnesses go stale.
type Verifier struct {
	embedded        EmbeddedReferences
	pinnedRegisters *measurement.Measurement
	freshnessMaxAge time.Duration
	ignoreFreshness bool

	configAuthorizer func(collateral.ConfigEndorsement) error

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
		return nil, usageError(err)
	}
	v := &Verifier{
		freshnessMaxAge: endorsement.MaxFreshnessAge,
		endorsements:    endorsementClient,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(v); err != nil {
			return nil, usageError(err)
		}
	}
	if v.embedded.Config != nil && v.configKeys != nil {
		return nil, usageError(fmt.Errorf("embedded config and config signing keys select conflicting trust sources"))
	}
	if v.configAuthorizer != nil && (v.embedded.Config != nil || v.configKeys != nil) {
		return nil, usageError(fmt.Errorf("config authorizer conflicts with embedded config or config signing keys"))
	}
	if v.embedded.Runtime != nil && v.embedded.Platform != nil && v.freshnessKeys != nil {
		return nil, usageError(fmt.Errorf("freshness signing keys have no endorsed artifact to verify"))
	}
	publicKeys, err := endorsement.PublicSigningKeys()
	if err != nil {
		return nil, usageError(err)
	}
	configKeys, freshnessKeys := v.configKeys, v.freshnessKeys
	if configKeys == nil {
		configKeys = publicKeys
	}
	if freshnessKeys == nil {
		freshnessKeys = publicKeys
	}
	v.configVerifier, err = v.endorsements.ConfigVerifier(configKeys)
	if err != nil {
		return nil, usageError(err)
	}
	v.freshnessVerifier, err = v.endorsements.FreshnessVerifier(freshnessKeys)
	if err != nil {
		return nil, usageError(err)
	}
	return v, nil
}

// ParseReference validates owner/name[@tag][@sha256:digest] and returns its parts.
func ParseReference(ref string) (repo, tag, digest string, err error) {
	parsed, err := endorsement.ParseReference(ref)
	return parsed.Repo, parsed.Tag, parsed.Digest, err
}

// FreshnessMaxAge reports the configured witness age bound.
func (v *Verifier) FreshnessMaxAge() time.Duration { return v.freshnessMaxAge }

// PinnedRegisters returns a copy of the configured register pins, or nil.
func (v *Verifier) PinnedRegisters() *measurement.Measurement {
	return cloneMeasurement(v.pinnedRegisters)
}

// VerifyV3 appraises a nonce-bound v3 attestation document using its collateral
// version. repo pins the expected repository or registry project as
// org/project[@revision][@sha256:digest]. An embedded config permits an empty
// repo; its exact caller-supplied bytes then provide the workload constraint.
// A config authorizer requires an empty repo and owns config authorization.
//
// The caller owns both expectations that cannot come from the document: the
// nonce it generated, and its workload constraint (repo or embedded bytes).
// On success it must bind traffic to the returned keys and enforce any nonzero
// FreshnessExpiresAt. With all references embedded, the caller owns renewal
// and cache lifetime; zero is not a guarantee of unlimited evidence validity.
func (v *Verifier) VerifyV3(docBytes, nonce []byte, repo string) (*Verification, error) {
	// The only clock read.
	return v.VerifyV3At(docBytes, nonce, repo, time.Now())
}

// VerifyV3At is VerifyV3 for an archived document. verificationTime replaces
// the current time in every time-bound check: the freshness witnesses and
// approvals, and the vendor certificate and CRL validity windows of the CPU
// evidence. VerifiedAt reports it, and a zero verificationTime is a
// UsageError.
//
// The caller must authenticate verificationTime independently, for example
// from a trusted timestamp recorded when the document was received. An
// earlier time accepts collateral that has since expired or been revoked, so
// live clients use VerifyV3.
func (v *Verifier) VerifyV3At(docBytes, nonce []byte, repo string, verificationTime time.Time) (*Verification, error) {
	verified, rejectedAt, err := v.verifyV3(docBytes, nonce, repo, verificationTime)
	// An error already carrying a verify type, such as the UsageError for a
	// caller's mistake, passes through; anything else becomes a
	// VerificationError for the layer that rejected the document.
	var classified Error
	if err == nil || errors.As(err, &classified) {
		return verified, err
	}
	return nil, &VerificationError{Layer: rejectedAt, Err: err}
}

type endorsementResult struct {
	quote              quote.ReferenceValues
	artifact           ArtifactVerification
	platform           *ArtifactVerification
	config             *ConfigVerification
	freshnessExpiresAt time.Time
}

// verifyV3 is VerifyV3 before classification: it returns the error a stage
// reported, a plain error for a rejected document or a UsageError for a
// caller's mistake, and the layer of that stage.
func (v *Verifier) verifyV3(docBytes, nonce []byte, repo string, now time.Time) (*Verification, Layer, error) {
	if v == nil || v.endorsements == nil || v.configVerifier == nil || v.freshnessVerifier == nil {
		return nil, "", &UsageError{Err: fmt.Errorf("verifier must be built with NewVerifier")}
	}
	if now.IsZero() {
		return nil, "", &UsageError{Err: fmt.Errorf("verification time must not be zero")}
	}
	doc, err := document.Parse(docBytes, nonce)
	if errors.Is(err, document.ErrInvalidInput) {
		return nil, LayerEnvelope, &UsageError{Err: err}
	}
	if err != nil {
		return nil, LayerEnvelope, err
	}

	// Reference values and CPU evidence are appraised against the same instant.
	var refs *endorsementResult
	switch doc.CollateralFormat() {
	case collateral.FormatV3:
		refs, err = v.configReferences(doc, repo, now)
	case collateral.FormatV2:
		refs, err = v.codeReferences(doc, repo, now)
	default:
		return nil, LayerProvenance, fmt.Errorf("unsupported collateral format %q", doc.CollateralFormat())
	}
	if err != nil {
		return nil, LayerProvenance, err
	}

	authenticated, err := quote.Authenticate(doc.CPUEvidence(), doc.CPUEndorsements(), now, v.quoteOptions())
	if err != nil {
		return nil, LayerQuote, err
	}
	assembled, err := quote.Assemble(doc, refs.quote, v.pinnedRegisters, authenticated)
	if err != nil {
		return nil, LayerPolicy, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, LayerPolicy, err
	}

	result := &Verification{
		ConfigRepo:         refs.artifact.Repo,
		CodeDigest:         refs.artifact.Digest,
		CodeTag:            refs.artifact.Tag,
		CodeMeasurement:    assembled.CodeMeasurement,
		Config:             refs.config,
		Platform:           refs.platform,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: refs.freshnessExpiresAt,
		Metadata: VerificationMetadata{
			Verifier:   SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()},
			VerifiedAt: now.UTC(),
		},
	}
	if refs.config != nil {
		result.Runtime = &refs.artifact
	}
	return result, "", nil
}

func (v *Verifier) codeReferences(doc *document.Document, repo string, appraisalTime time.Time) (*endorsementResult, error) {
	if v.requiresConfigCollateral() {
		return nil, fmt.Errorf("configured trust requires %s", collateral.FormatV3)
	}
	codeRef, err := doc.SigstoreCode()
	if err != nil {
		return nil, err
	}
	pin, err := endorsement.ParseReference(repo)
	if err != nil {
		return nil, usageError(err)
	}
	code, err := v.endorsements.AuthenticateCode(codeRef.Bundle, pin, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, err
	}
	platformRef, err := doc.SigstorePlatform()
	if err != nil {
		return nil, err
	}
	endorsements, err := v.endorsements.AuthenticatePlatformEndorsements(platformRef.Bundle, platformRef.Repo, platformRef.Tag, platformRef.Digest, policy.ArtifactFormat)
	if err != nil {
		return nil, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	refs := &endorsementResult{
		quote: quote.LegacyReferenceValues{
			Endorsements: endorsements.Artifact, Code: code.Measurement, Shape: code.Shape,
		},
		artifact: artifactVerification(code.AuthenticatedArtifact, time.Time{}),
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
		if !issuedAt.IsZero() && (first.IsZero() || issuedAt.Before(first)) {
			first = issuedAt
		}
	}
	if first.IsZero() {
		return time.Time{}
	}
	return first.Add(maxAge)
}
