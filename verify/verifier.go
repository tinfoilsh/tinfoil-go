// Package verify appraises Tinfoil attestation documents.
//
// It is the functional core of the SDK: given a document, the nonce the caller
// bound it to, and what the caller trusts — a code repository, or the identity
// of a config a registry approved — a Verifier decides what the document
// proves. It opens no connections and keeps no state between
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
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
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
	identity        SoftwareIdentity

	// provenance authenticates reference values against its own copy of the
	// trusted root. NewVerifier builds one from the embedded root; only the
	// conformance build can replace it.
	provenance *provenance.Client

	// configKeys are the registry keys the application provisioned, and
	// configVerifier the verifier NewVerifier builds from them. Both are nil
	// unless WithConfigSigningKeys was given.
	configKeys     []endorsement.SigningKey
	configVerifier *endorsement.Verifier

	// overrides is empty in a production build; the conformance build uses it
	// to carry synthetic vendor roots down to the CPU evidence layer.
	overrides overrides
}

// NewVerifier builds a Verifier from opts. With no options it appraises against
// the release measurements alone, with the seven-day freshness bound.
func NewVerifier(opts ...Option) (*Verifier, error) {
	// Build default provenance.Client with embedded roots
	provenanceClient, err := provenance.NewDefaultClient()
	if err != nil {
		return nil, configurationError(err)
	}
	v := &Verifier{
		freshnessMaxAge: provenance.MaxFreshnessAge,
		now:             time.Now,
		identity:        SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()},
		provenance:      provenanceClient,
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
		if v.configVerifier, err = v.provenance.ConfigVerifier(v.configKeys); err != nil {
			return nil, configurationError(err)
		}
		v.configKeys = nil
	}
	return v, nil
}

// ParseReference validates owner/name[@tag][@sha256:digest] and returns its parts.
func ParseReference(ref string) (repo, tag, digest string, err error) {
	return provenance.ParseReference(ref)
}

// Identity reports the verifier recorded in each result's metadata.
func (v *Verifier) Identity() SoftwareIdentity { return v.identity }

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
	if _, _, _, err := provenance.ParseReference(repo); err != nil {
		return nil, configurationError(err)
	}
	verified, _, err := v.verifyV3(docBytes, nonce, func(doc *document.Document, at time.Time) (*references, error) {
		return v.codeReferences(doc, repo, at)
	})
	return verified, err
}

// VerifyConfig appraises a nonce-bound v3 attestation document whose guest
// booted a cvmimage IGVM image. pin is the config the caller trusts; the keys
// that may approve it come from WithConfigSigningKeys. The document names the
// runtime release, and a freshness witness is what refuses a withdrawn one.
func (v *Verifier) VerifyConfig(docBytes, nonce []byte, pin ConfigPin) (*Verification, error) {
	if err := v.checkConfigPin(pin); err != nil {
		return nil, configurationError(err)
	}
	verified, _, err := v.verifyV3(docBytes, nonce, func(doc *document.Document, at time.Time) (*references, error) {
		return v.configReferences(doc, pin, at)
	})
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

// referenceValues authenticates everything a document is appraised against.
// Which flow is running is entirely its business.
type referenceValues func(doc *document.Document, appraisalTime time.Time) (*references, error)

// references is what a flow gathered, all of it authenticated.
type references struct {
	// Code is the release the expected measurement came from.
	*provenance.Code
	// Endorsements is the appraisal policy, with any config binding already
	// resolved into a concrete expectation.
	Endorsements *policy.Artifact
	// ConfigRepo is the repository the code artifact was pinned to.
	ConfigRepo string
	// Config is the registry approval, which only the config flow has.
	Config *endorsement.Verified
	// FreshnessExpiresAt is the earliest authenticated deadline among the
	// witnesses and approvals the flow required.
	FreshnessExpiresAt time.Time
}

// verifyV3 is VerifyV3 or VerifyConfig, also reporting which layer rejected the document.
func (v *Verifier) verifyV3(docBytes, nonce []byte, gather referenceValues) (*Verification, layer, error) {
	if v == nil || v.now == nil || v.provenance == nil {
		return nil, layerNone, &errs.ConfigurationError{Err: fmt.Errorf("verifier must be built with NewVerifier")}
	}
	doc, err := document.Parse(docBytes, nonce)
	if err != nil {
		return nil, layerEnvelope, err
	}

	// Sampled once, so freshness appraisal and the CPU evidence windows judge
	// this document against the same instant.
	now := v.now()

	refs, err := gather(doc, now)
	if err != nil {
		return nil, layerProvenance, errs.WrapAttestation(fmt.Errorf("reference values: %w", err))
	}

	authenticated, err := quote.Authenticate(doc.CPUEvidence(), doc.CPUEndorsements(), v.quoteOptions(now))
	if err != nil {
		return nil, layerQuote, err
	}
	assembled, err := quote.Assemble(doc, refs.Endorsements, refs.Measurement, v.pinnedRegisters, refs.Shape, authenticated)
	if err != nil {
		return nil, layerPolicy, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, layerPolicy, err
	}

	return &Verification{
		ConfigRepo:         refs.ConfigRepo,
		CodeDigest:         refs.Digest,
		CodeTag:            refs.Tag,
		CodeMeasurement:    refs.Measurement,
		Config:             refs.Config,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: refs.FreshnessExpiresAt,
		Metadata: VerificationMetadata{
			Verifier:   v.identity,
			VerifiedAt: now.UTC(),
		},
	}, layerNone, nil
}

// codeReferences gathers the reference values of the code-provenance flow:
// the measurement comes from a code artifact the pinned repository signed.
func (v *Verifier) codeReferences(doc *document.Document, repo string, appraisalTime time.Time) (*references, error) {
	configRepo, _, _, err := provenance.ParseReference(repo)
	if err != nil {
		return nil, err
	}
	codeRef, err := doc.SigstoreCode()
	if err != nil {
		return nil, err
	}
	code, err := v.provenance.AuthenticateCode(codeRef.Bundle, repo, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, fmt.Errorf("verifying code measurement: %w", err)
	}
	endorsements, err := v.authenticatePlatform(doc)
	if err != nil {
		return nil, err
	}
	refs := &references{Code: code, Endorsements: endorsements.Artifact, ConfigRepo: configRepo}
	if v.ignoreFreshness {
		return refs, nil
	}
	codeWitnessedAt, err := v.witness(doc, collateral.FreshnessIDCode, &code.AuthenticatedArtifact, appraisalTime, "code")
	if err != nil {
		return nil, err
	}
	platformWitnessedAt, err := v.witness(doc, collateral.FreshnessIDPlatform, &endorsements.AuthenticatedArtifact, appraisalTime, "platform")
	if err != nil {
		return nil, err
	}
	refs.FreshnessExpiresAt = freshnessExpiration(v.freshnessMaxAge, codeWitnessedAt, platformWitnessedAt)
	return refs, nil
}

func (v *Verifier) authenticatePlatform(doc *document.Document) (*provenance.PlatformEndorsements, error) {
	platformRef, err := doc.SigstorePlatform()
	if err != nil {
		return nil, err
	}
	endorsements, err := v.provenance.AuthenticatePlatformEndorsements(platformRef.Bundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	return endorsements, nil
}

// witness authenticates the freshness witness with the given collateral ID
// against an already-authenticated artifact.
func (v *Verifier) witness(doc *document.Document, id string, artifact *provenance.AuthenticatedArtifact, appraisalTime time.Time, label string) (time.Time, error) {
	freshness, err := doc.Freshness(id)
	if err != nil {
		return time.Time{}, err
	}
	witnessedAt, err := v.provenance.AuthenticateFreshness(freshness.Bundle, artifact, appraisalTime, v.freshnessMaxAge)
	if err != nil {
		return time.Time{}, fmt.Errorf("verifying %s freshness: %w", label, err)
	}
	return witnessedAt, nil
}

// freshnessExpiration uses authenticated witness times, never local verification time.
// At least one is required: a zero expiry already means "do not authorize new requests".
func freshnessExpiration(maxAge time.Duration, witnessedAt time.Time, more ...time.Time) time.Time {
	expiresAt := witnessedAt.Add(maxAge)
	for _, at := range more {
		if deadline := at.Add(maxAge); deadline.Before(expiresAt) {
			expiresAt = deadline
		}
	}
	return expiresAt
}
