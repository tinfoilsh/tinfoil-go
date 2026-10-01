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

// ErrCollateralNotFound reports that a parsed document carries no collateral
// entry for the requested purpose. Malformed collateral never reaches the
// accessors, because Parse rejects it. Verification classifies missing
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

// collateralSet is a document's collateral as Parse decoded it: for each
// purpose the verifier knows, the first entry serving it. An entry whose role
// and format the verifier has no decoder for (an unknown format, a known
// format under another role, or CollateralConfigEndorsementV1Format until a
// consumer defines its payload) is checked for shape only and not retained.
type collateralSet struct {
	amdVCEK          *AMDVCEK
	amdCRL           *AMDCRL
	intelPCS         *IntelPCS
	sigstoreCode     *SigstoreRef
	sigstorePlatform *SigstoreRef
	freshness        map[string]Freshness
}

// decodeCollateral decodes every entry of a known role and format, so a
// malformed entry fails Parse whether or not verification would read it. An
// endorsement entry serves the CPU only when its subjects include SubjectCPU.
func decodeCollateral(entries []CollateralEntry) (collateralSet, error) {
	set := collateralSet{freshness: make(map[string]Freshness)}
	for i := range entries {
		entry := &entries[i]
		cpu := slices.Contains(entry.Subjects, SubjectCPU)
		switch {
		case entry.Role == RoleEndorsement && entry.Format == CollateralAMDVCEKV1Format:
			v, err := decodeAMDVCEK(entry)
			if err != nil {
				return set, err
			}
			if cpu && set.amdVCEK == nil {
				set.amdVCEK = v
			}
		case entry.Role == RoleEndorsement && entry.Format == CollateralAMDCRLV1Format:
			v, err := decodeAMDCRL(entry)
			if err != nil {
				return set, err
			}
			if cpu && set.amdCRL == nil {
				set.amdCRL = v
			}
		case entry.Role == RoleEndorsement && entry.Format == CollateralIntelPCSV1Format:
			v, err := decodeIntelPCS(entry)
			if err != nil {
				return set, err
			}
			if cpu && set.intelPCS == nil {
				set.intelPCS = v
			}
		case entry.Role == RoleReferenceValues && entry.Format == CollateralSigstoreCodeV1Format:
			v, err := decodeSigstoreRef(entry)
			if err != nil {
				return set, err
			}
			if set.sigstoreCode == nil {
				set.sigstoreCode = v
			}
		case entry.Role == RoleReferenceValues && entry.Format == CollateralSigstorePlatformV1Format:
			v, err := decodeSigstoreRef(entry)
			if err != nil {
				return set, err
			}
			if set.sigstorePlatform == nil {
				set.sigstorePlatform = v
			}
		case entry.Role == RoleReferenceValues && entry.Format == CollateralSigstoreFreshnessV1Format:
			var data freshnessCollateral
			if err := unmarshalCollateral(entry, entry.Format, &data); err != nil {
				return set, err
			}
			if err := requireBundle(entry, data.SigstoreBundle); err != nil {
				return set, err
			}
			// validateCollateral already rejected duplicate IDs.
			set.freshness[entry.ID] = Freshness{Bundle: data.SigstoreBundle}
		}
	}
	return set, nil
}

func unmarshalCollateral(entry *CollateralEntry, label string, v any) error {
	if err := json.Unmarshal(entry.Data, v, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("parsing %s collateral entry %q: %w", label, entry.ID, err)
	}
	return nil
}

func decodeAMDVCEK(entry *CollateralEntry) (*AMDVCEK, error) {
	var data amdVCEKCollateral
	if err := unmarshalCollateral(entry, "amd-vcek", &data); err != nil {
		return nil, err
	}
	der, err := data.vcekDER()
	if err != nil {
		return nil, fmt.Errorf("amd-vcek collateral entry %q: %w", entry.ID, err)
	}
	return &AMDVCEK{VCEKDER: der, CertChainPEM: data.CertChainPEM}, nil
}

func decodeAMDCRL(entry *CollateralEntry) (*AMDCRL, error) {
	var data amdCRLCollateral
	if err := unmarshalCollateral(entry, "amd-crl", &data); err != nil {
		return nil, err
	}
	der, err := data.crlDER()
	if err != nil {
		return nil, fmt.Errorf("amd-crl collateral entry %q: %w", entry.ID, err)
	}
	return &AMDCRL{CRLDER: der}, nil
}

func decodeIntelPCS(entry *CollateralEntry) (*IntelPCS, error) {
	var data intelPCSCollateral
	if err := unmarshalCollateral(entry, "intel-pcs", &data); err != nil {
		return nil, err
	}
	pcs := &IntelPCS{Responses: make([]PCSResponse, 0, len(data.Responses))}
	for i := range data.Responses {
		body, err := data.Responses[i].body()
		if err != nil {
			return nil, fmt.Errorf("intel-pcs collateral entry %q response %d: %w", entry.ID, i, err)
		}
		pcs.Responses = append(pcs.Responses, PCSResponse{URL: data.Responses[i].URL, Headers: data.Responses[i].Headers, Body: body})
	}
	return pcs, nil
}

func decodeSigstoreRef(entry *CollateralEntry) (*SigstoreRef, error) {
	var data sigstoreCollateral
	if err := unmarshalCollateral(entry, entry.Format, &data); err != nil {
		return nil, err
	}
	// Tag is an optional hint and Repo is checked by provenance where it
	// matters; the digest and bundle are what verification needs.
	if data.Digest == "" {
		return nil, fmt.Errorf("%s collateral entry %q is missing digest", entry.Format, entry.ID)
	}
	if err := requireBundle(entry, data.SigstoreBundle); err != nil {
		return nil, err
	}
	return &SigstoreRef{Repo: data.Repo, Tag: data.Tag, Digest: data.Digest, Bundle: data.SigstoreBundle}, nil
}

// requireBundle rejects an entry whose sigstore_bundle member is missing or
// null. Whether a present bundle verifies is for provenance to judge.
func requireBundle(entry *CollateralEntry, bundle jsontext.Value) error {
	if len(bundle) == 0 || bundle.Kind() == 'n' {
		return fmt.Errorf("%s collateral entry %q is missing sigstore_bundle", entry.Format, entry.ID)
	}
	return nil
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

// Clone returns a deep copy of r.
func (r SigstoreRef) Clone() SigstoreRef {
	r.Bundle = slices.Clone(r.Bundle)
	return r
}

// Freshness is a decoded freshness witness: the independently signed bundle
// that attests a reference-values artifact was recently published.
type Freshness struct {
	Bundle jsontext.Value
}

// Clone returns a deep copy of f.
func (f Freshness) Clone() Freshness {
	return Freshness{Bundle: slices.Clone(f.Bundle)}
}

// SigstoreCode returns the code-provenance reference-values entry. A document
// without one returns an error wrapping ErrCollateralNotFound.
func (d *Document) SigstoreCode() (SigstoreRef, error) {
	return sigstoreRef(d.collateral.sigstoreCode, CollateralSigstoreCodeV1Format)
}

// SigstorePlatform returns the platform-endorsements reference-values entry.
// A document without one returns an error wrapping ErrCollateralNotFound.
func (d *Document) SigstorePlatform() (SigstoreRef, error) {
	return sigstoreRef(d.collateral.sigstorePlatform, CollateralSigstorePlatformV1Format)
}

func sigstoreRef(ref *SigstoreRef, format string) (SigstoreRef, error) {
	if ref == nil {
		return SigstoreRef{}, fmt.Errorf("%w: document carries no %s reference-values entry", ErrCollateralNotFound, format)
	}
	return ref.Clone(), nil
}

// Freshness returns the freshness witness with the given collateral ID, such
// as FreshnessCollateralIDCode. A document without it returns an error
// wrapping ErrCollateralNotFound.
func (d *Document) Freshness(id string) (Freshness, error) {
	f, ok := d.collateral.freshness[id]
	if !ok {
		return Freshness{}, fmt.Errorf("%w: document carries no %s reference-values entry %q", ErrCollateralNotFound, CollateralSigstoreFreshnessV1Format, id)
	}
	return f.Clone(), nil
}
