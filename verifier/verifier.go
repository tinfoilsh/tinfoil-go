// Package verifier appraises Tinfoil attestation documents.
//
// It is the functional core of the SDK: given a document, the nonce the caller
// bound it to, and the repository the caller trusts, a Verifier decides what
// the document proves. It opens no connections and keeps no state between
// calls, so fetching documents, caching a verification and enforcing its
// expiry all belong to the caller — see verifier/client for an implementation
// that does those things.
//
// This package also re-exports the SDK's error categories, which are defined
// in verifier/errs so the lower-level verification packages can classify their
// errors without importing this one, which imports them in turn.
package verifier

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
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
// overrides.go); only the conformance build threads one through. Either way,
// the same document is accepted today and rejected once its witnesses go
// stale.
type Verifier struct {
	pinnedRegisters *measurement.Measurement
	freshnessMaxAge time.Duration
	now             func() time.Time
}

// New builds a Verifier from opts. With no options it appraises against the
// release measurements alone, with the seven-day freshness bound.
func New(opts ...Option) (*Verifier, error) {
	v := &Verifier{
		freshnessMaxAge: provenance.MaxFreshnessAge,
		now:             time.Now,
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
	if v == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("verifier is required")}
	}
	if _, _, _, err := provenance.ParseReference(repo); err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	doc, expectedReportData, err := document.Check(docBytes, nonce)
	if err != nil {
		return nil, err
	}

	// Sampled once, so freshness appraisal and the CPU evidence windows judge
	// this document against the same instant.
	now := v.now()

	code, endorsements, freshnessExpiresAt, err := v.authenticateReferenceValues(doc, repo, now)
	if err != nil {
		return nil, errs.WrapAttestation(fmt.Errorf("reference values: %w", err))
	}

	_, authenticated, err := quote.Verify(doc, endorsements.Artifact, code.Measurement, v.pinnedRegisters, code.Shape, expectedReportData, v.quoteOptions(now))
	if err != nil {
		return nil, err
	}

	return &Verification{
		CodeDigest:         code.Digest,
		CodeTag:            code.Tag,
		CodeMeasurement:    code.Measurement,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: freshnessExpiresAt,
	}, nil
}

func (v *Verifier) authenticateReferenceValues(doc *document.Document, repo string, appraisalTime time.Time) (*provenance.Code, *provenance.PlatformEndorsements, time.Time, error) {
	codeRef, err := doc.ReferenceValuesCollateral(document.CollateralSigstoreCodeV1Format)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	code, err := provenance.AuthenticateCode(codeRef.SigstoreBundle, repo, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code measurement: %w", err)
	}
	codeFreshnessRef, err := doc.FreshnessCollateral(document.FreshnessCollateralIDCode)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	codeWitnessedAt, err := provenance.AuthenticateFreshness(codeFreshnessRef.SigstoreBundle, &code.AuthenticatedArtifact, appraisalTime, v.freshnessMaxAge)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code freshness: %w", err)
	}

	platformRef, err := doc.ReferenceValuesCollateral(document.CollateralSigstorePlatformV1Format)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	endorsements, err := provenance.AuthenticatePlatformEndorsements(platformRef.SigstoreBundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	freshnessRef, err := doc.FreshnessCollateral(document.FreshnessCollateralIDPlatform)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	platformWitnessedAt, err := provenance.AuthenticateFreshness(freshnessRef.SigstoreBundle, &endorsements.AuthenticatedArtifact, appraisalTime, v.freshnessMaxAge)
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
