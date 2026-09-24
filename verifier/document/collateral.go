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

// AMDVCEKCollateral is the data of a CollateralAMDVCEKV1Format entry.
type AMDVCEKCollateral struct {
	VCEKDERBase64 string `json:"vcek_der_base64"`
	CertChainPEM  string `json:"cert_chain_pem"`
}

// AMDCRLCollateral is the data of a CollateralAMDCRLV1Format entry.
type AMDCRLCollateral struct {
	CRLDERBase64 string `json:"crl_der_base64"`
}

// IntelPCSCollateral is the data of a CollateralIntelPCSV1Format entry:
// Intel PCS responses captured verbatim so a verifier can replay them
// instead of fetching. Headers are included because Intel delivers issuer
// chains in response headers.
type IntelPCSCollateral struct {
	Responses []PCSResponse `json:"responses"`
}

// PCSResponse is one captured Intel PCS response.
type PCSResponse struct {
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
}

// SigstoreCollateral is the data of a sigstore-code or sigstore-platform
// reference-values entry. Repo and Tag are informational; trust comes from
// verifying SigstoreBundle against the expected signing identity and Digest.
type SigstoreCollateral struct {
	Repo           string         `json:"repo"`
	Tag            string         `json:"tag"`
	Digest         string         `json:"digest"`
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

// FreshnessCollateral carries the independently signed witness bundle for
// the Sigstore artifact selected by its collateral entry ID.
type FreshnessCollateral struct {
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
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

// EndorsementCollateral returns the first endorsement-role collateral entry
// with the given format whose subjects include subject.
func (d *Document) EndorsementCollateral(format, subject string) (*CollateralEntry, bool) {
	entry := d.findCollateral(RoleEndorsement, format, func(entry *CollateralEntry) bool {
		return slices.Contains(entry.Subjects, subject)
	})
	return entry, entry != nil
}

// ReferenceValuesCollateral returns the first reference-values collateral
// entry with the given format, parsed as a Sigstore collateral payload. A
// document without such an entry returns an error wrapping
// ErrCollateralNotFound.
func (d *Document) ReferenceValuesCollateral(format string) (*SigstoreCollateral, error) {
	entry := d.findCollateral(RoleReferenceValues, format, nil)
	if entry == nil {
		return nil, fmt.Errorf("%w: document carries no %s reference-values entry", ErrCollateralNotFound, format)
	}
	return decodeCollateral[SigstoreCollateral](entry)
}

// FreshnessCollateral returns the reference-values freshness payload with the
// requested artifact ID. Parse validates collateral ID uniqueness.
func (d *Document) FreshnessCollateral(id string) (*FreshnessCollateral, error) {
	entry := d.findCollateral(RoleReferenceValues, CollateralSigstoreFreshnessV1Format, func(entry *CollateralEntry) bool {
		return entry.ID == id
	})
	if entry == nil {
		return nil, fmt.Errorf("%w: document carries no %s reference-values entry %q", ErrCollateralNotFound, CollateralSigstoreFreshnessV1Format, id)
	}
	return decodeCollateral[FreshnessCollateral](entry)
}

// findCollateral selects the first matching entry; Parse validates uniqueness.
func (d *Document) findCollateral(role, format string, match func(*CollateralEntry) bool) *CollateralEntry {
	for i := range d.Collateral {
		entry := &d.Collateral[i]
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
