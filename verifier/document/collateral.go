package document

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
)

// Collateral roles (RATS, RFC 9334).
const (
	// RoleEndorsement labels hardware-vendor material used to
	// cryptographically verify evidence (e.g. AMD VCEK chains, Intel PCS).
	RoleEndorsement = "endorsement"
	// RoleReferenceValues labels Tinfoil-signed expectations used to
	// appraise verified evidence.
	RoleReferenceValues = "reference-values"
)

// CollateralEntry is one self-describing collateral record. Collateral is
// unendorsed transport: every entry is authenticated by its own signature
// chain during verification, so a tampered entry can only cause rejection.
type CollateralEntry struct {
	ID       string         `json:"id"`
	Role     string         `json:"role"`
	Format   string         `json:"format"`
	Subjects []string       `json:"subjects,omitempty"`
	Data     jsontext.Value `json:"data"`
}

// amdVCEKCollateral is the data of a CollateralAMDVCEKV1Format entry.
type amdVCEKCollateral struct {
	VCEKDERBase64 string `json:"vcek_der_base64"`
	CertChainPEM  string `json:"cert_chain_pem"`
}

// vcekDER decodes VCEKDERBase64, rejecting non-canonical base64.
func (c *amdVCEKCollateral) vcekDER() ([]byte, error) {
	return decodeCanonicalBase64("vcek_der_base64", c.VCEKDERBase64)
}

// amdCRLCollateral is the data of a CollateralAMDCRLV1Format entry.
type amdCRLCollateral struct {
	CRLDERBase64 string `json:"crl_der_base64"`
}

// crlDER decodes CRLDERBase64, rejecting non-canonical base64.
func (c *amdCRLCollateral) crlDER() ([]byte, error) {
	return decodeCanonicalBase64("crl_der_base64", c.CRLDERBase64)
}

// intelPCSCollateral is the data of a CollateralIntelPCSV1Format entry:
// Intel PCS responses captured verbatim so a verifier can replay them
// instead of fetching. Headers are included because Intel delivers issuer
// chains in response headers.
type intelPCSCollateral struct {
	Responses []rawPCSResponse `json:"responses"`
}

// rawPCSResponse is one captured Intel PCS response as serialized.
type rawPCSResponse struct {
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
}

// body decodes BodyBase64, rejecting non-canonical base64.
func (r *rawPCSResponse) body() ([]byte, error) {
	return decodeCanonicalBase64("body_base64", r.BodyBase64)
}

// sigstoreCollateral is the data of a sigstore-code or sigstore-platform
// reference-values entry. Repo and Tag are informational; trust comes from
// verifying SigstoreBundle against the expected signing identity and Digest.
type sigstoreCollateral struct {
	Repo           string         `json:"repo"`
	Tag            string         `json:"tag"`
	Digest         string         `json:"digest"`
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

// freshnessCollateral carries the independently signed witness bundle for
// the Sigstore artifact selected by its collateral entry ID.
type freshnessCollateral struct {
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

// ConfigReference identifies immutable registry bytes; it does not select the
// signing keys or audit scope trusted by a verifier.
type ConfigReference struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// ErrCollateralNotFound reports that a document carries no collateral entry
// of the requested role and format. Low-level callers may use errors.Is to
// distinguish absence from malformed collateral. Verification classifies missing
// required collateral as an AttestationError while preserving this cause.
var ErrCollateralNotFound = errors.New("collateral entry not found")

func validateCollateral(entries []CollateralEntry) error {
	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		if entry.ID == "" || entry.Format == "" {
			return fmt.Errorf("collateral entry %d is incomplete", i)
		}
		if seen[entry.ID] {
			return fmt.Errorf("duplicate collateral entry id %q", entry.ID)
		}
		seen[entry.ID] = true
		if entry.Role != RoleEndorsement && entry.Role != RoleReferenceValues {
			return fmt.Errorf("collateral entry %q has unknown role %q", entry.ID, entry.Role)
		}
	}
	return nil
}

// endorsementCollateral returns the first endorsement-role collateral entry
// with the given format whose subjects include subject.
func (d *Document) endorsementCollateral(format, subject string) (*CollateralEntry, bool) {
	entry := d.findCollateral(RoleEndorsement, format, func(entry *CollateralEntry) bool {
		return slices.Contains(entry.Subjects, subject)
	})
	return entry, entry != nil
}

// referenceValues returns the first reference-values collateral
// entry with the given format, parsed as a Sigstore collateral payload. A
// document without such an entry returns an error wrapping
// ErrCollateralNotFound.
func (d *Document) referenceValues(format string) (*sigstoreCollateral, error) {
	entry := d.findCollateral(RoleReferenceValues, format, nil)
	if entry == nil {
		return nil, fmt.Errorf("%w: document carries no %s reference-values entry", ErrCollateralNotFound, format)
	}
	return decodeCollateral[sigstoreCollateral](entry)
}

// freshnessEntry returns the reference-values freshness payload with the
// requested artifact ID. Parse validates collateral ID uniqueness.
func (d *Document) freshnessEntry(id string) (*freshnessCollateral, error) {
	entry := d.findCollateral(RoleReferenceValues, CollateralSigstoreFreshnessV1Format, func(entry *CollateralEntry) bool {
		return entry.ID == id
	})
	if entry == nil {
		return nil, fmt.Errorf("%w: document carries no %s reference-values entry %q", ErrCollateralNotFound, CollateralSigstoreFreshnessV1Format, id)
	}
	return decodeCollateral[freshnessCollateral](entry)
}

// SigstoreRef is a decoded reference-values entry: a Sigstore bundle and the
// release it names. Repo and Tag are informational; trust comes from
// verifying Bundle against the expected signing identity and Digest.
type SigstoreRef struct {
	Repo   string
	Tag    string
	Digest string
	Bundle jsontext.Value
}

// Freshness is a decoded freshness witness: the independently signed bundle
// that attests a reference-values artifact was recently published.
type Freshness struct {
	Bundle jsontext.Value
}

// SigstoreCode returns the code-provenance reference-values entry. A document
// without one returns an error wrapping ErrCollateralNotFound.
func (d *Document) SigstoreCode() (SigstoreRef, error) {
	return d.sigstoreRef(CollateralSigstoreCodeV1Format)
}

// SigstorePlatform returns the platform-endorsements reference-values entry.
// A document without one returns an error wrapping ErrCollateralNotFound.
func (d *Document) SigstorePlatform() (SigstoreRef, error) {
	return d.sigstoreRef(CollateralSigstorePlatformV1Format)
}

func (d *Document) sigstoreRef(format string) (SigstoreRef, error) {
	c, err := d.referenceValues(format)
	if err != nil {
		return SigstoreRef{}, err
	}
	return SigstoreRef{Repo: c.Repo, Tag: c.Tag, Digest: c.Digest, Bundle: c.SigstoreBundle}, nil
}

// Freshness returns the freshness witness with the given collateral ID, such
// as FreshnessCollateralIDCode. A document without it returns an error
// wrapping ErrCollateralNotFound.
func (d *Document) Freshness(id string) (Freshness, error) {
	c, err := d.freshnessEntry(id)
	if err != nil {
		return Freshness{}, err
	}
	return Freshness{Bundle: c.SigstoreBundle}, nil
}

// findCollateral selects the first matching entry; Parse validates uniqueness.
func (d *Document) findCollateral(role, format string, match func(*CollateralEntry) bool) *CollateralEntry {
	for i := range d.collateral {
		entry := &d.collateral[i]
		if entry.Role == role && entry.Format == format && (match == nil || match(entry)) {
			return entry
		}
	}
	return nil
}

func decodeCollateral[T any](entry *CollateralEntry) (*T, error) {
	var payload T
	if err := json.Unmarshal(entry.Data, &payload, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parsing %s collateral entry %q: %w", entry.Format, entry.ID, err)
	}
	return &payload, nil
}
