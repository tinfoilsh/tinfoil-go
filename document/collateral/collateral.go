// Package collateral defines the collateral entries a v3 attestation document
// carries and their strict decoding. Collateral is unendorsed transport: every
// entry is authenticated by its own signature chain during verification, so a
// decoded entry is not trusted and a tampered one can only cause rejection.
package collateral

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
)

// Collateral format registry (v3).
const (
	// AMDVCEKV1Format carries {vcek_der_base64, cert_chain_pem}.
	AMDVCEKV1Format = "https://tinfoil.sh/collateral/amd-vcek/v1"
	// AMDCRLV1Format carries {crl_der_base64}: the AMD KDS CRL for the product
	// line, enabling offline VCEK revocation checking.
	AMDCRLV1Format = "https://tinfoil.sh/collateral/amd-crl/v1"
	// IntelPCSV1Format carries captured Intel PCS responses (TCB info, QE
	// identity, CRLs) for offline TDX quote verification.
	IntelPCSV1Format = "https://tinfoil.sh/collateral/intel-pcs/v1"
	// NvidiaGPUV1Format carries NVIDIA cert chains / RIM material.
	NvidiaGPUV1Format = "https://tinfoil.sh/collateral/nvidia-gpu/v1"
	// SigstoreCodeV1Format carries the code-provenance Sigstore bundle
	// {repo, tag, digest, sigstore_bundle}.
	SigstoreCodeV1Format = "https://tinfoil.sh/collateral/sigstore-code/v1"
	// SigstorePlatformV1Format carries the platform-endorsements Sigstore
	// bundle {repo, tag, digest, sigstore_bundle}.
	SigstorePlatformV1Format = "https://tinfoil.sh/collateral/sigstore-platform/v1"
	// SigstoreFreshnessV1Format carries a freshness witness for a Sigstore
	// reference-values artifact.
	SigstoreFreshnessV1Format = "https://tinfoil.sh/collateral/sigstore-freshness/v1"
	// ArtifactFreshnessV1Format carries a Tinfoil-signed release approval.
	ArtifactFreshnessV1Format = "https://tinfoil.sh/collateral/artifact-freshness/v1"
	// ConfigEndorsementV1Format carries an exact config and its timestamped
	// registry approval bundle.
	ConfigEndorsementV1Format = "https://tinfoil.sh/collateral/config-endorsement/v1"
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

// Conventional identifiers.
const (
	// SubjectCPU is the reserved collateral subject id for the CPU quote.
	SubjectCPU = "cpu"
	// Freshness entry IDs associate each freshness witness with the Sigstore
	// reference-values entry it refreshes.
	FreshnessIDCode     = "code-freshness"
	FreshnessIDPlatform = "platform-freshness"
	FreshnessIDRuntime  = "runtime-freshness"
	// ConfigID is the ID of the config-endorsement entry.
	ConfigID = "tinfoil-config"
)

// Entry is one self-describing collateral record.
type Entry struct {
	ID       string         `json:"id"`
	Role     string         `json:"role"`
	Format   string         `json:"format"`
	Subjects []string       `json:"subjects,omitempty"`
	Data     jsontext.Value `json:"data"`
}

// ConfigReference identifies immutable registry bytes; it does not select the
// signing keys or audit scope trusted by a verifier.
type ConfigReference struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// ErrNotFound reports that a document carries no collateral entry for the
// requested purpose. Malformed collateral never reaches the document's
// accessors, because Decode rejects it. Verification classifies missing
// required collateral as an AttestationError while preserving this cause.
var ErrNotFound = errors.New("collateral entry not found")

// Set is decoded collateral: for each purpose the verifier knows, the first
// entry serving it. A nil field means no entry serves that purpose.
type Set struct {
	// CPU is the endorsement collateral for SubjectCPU, of every platform.
	CPU              CPUEndorsements
	SigstoreCode     *SigstoreRef
	SigstorePlatform *SigstoreRef
	Config           *ConfigEndorsement
	Runtime          *Runtime
	platformCount    int
	configPlatform   *SigstoreRef
	// Freshness holds the freshness witnesses by entry ID.
	Freshness map[string]Freshness
}

// Decode checks the entries' shape and decodes every entry of a known role and
// format, so a malformed entry fails whether or not verification would read
// it. An entry whose role and format have no decoder (an unknown format, a
// known format under another role) is checked for shape only and not retained.
// Config and runtime entries require their reserved IDs, formats, and roles.
// An endorsement entry serves the CPU only when its subjects include
// SubjectCPU.
func Decode(entries []Entry) (Set, error) {
	set := Set{Freshness: make(map[string]Freshness)}
	if err := validate(entries); err != nil {
		return set, err
	}
	for i := range entries {
		entry := &entries[i]
		cpu := slices.Contains(entry.Subjects, SubjectCPU)
		if entry.ID == PlatformID || entry.Format == SigstorePlatformV1Format {
			set.platformCount++
		}
		switch {
		case entry.ID == ConfigID || entry.Format == ConfigEndorsementV1Format:
			if entry.ID != ConfigID || entry.Format != ConfigEndorsementV1Format || entry.Role != RoleReferenceValues {
				return set, fmt.Errorf("conflicting collateral entry for %q", ConfigID)
			}
			v, err := decodeConfigEndorsement(entry)
			if err != nil {
				return set, err
			}
			set.Config = &v
		case entry.ID == RuntimeID || entry.Format == RuntimeV1Format:
			if entry.ID != RuntimeID || entry.Format != RuntimeV1Format || entry.Role != RoleReferenceValues {
				return set, fmt.Errorf("conflicting collateral entry for %q", RuntimeID)
			}
			v, err := decodeRuntime(entry)
			if err != nil {
				return set, err
			}
			set.Runtime = &v
		case entry.Format == ArtifactFreshnessV1Format || entry.ID == FreshnessIDRuntime:
			if (entry.ID != FreshnessIDPlatform && entry.ID != FreshnessIDRuntime) || entry.Format != ArtifactFreshnessV1Format || entry.Role != RoleReferenceValues {
				return set, fmt.Errorf("conflicting artifact freshness collateral %q", entry.ID)
			}
			f, err := decodeFreshness(entry)
			if err != nil {
				return set, err
			}
			set.Freshness[entry.ID] = f
		case entry.Role == RoleEndorsement && entry.Format == AMDVCEKV1Format:
			v, err := decodeAMDVCEK(entry)
			if err != nil {
				return set, err
			}
			if cpu && set.CPU.AMDVCEK == nil {
				set.CPU.AMDVCEK = v
			}
		case entry.Role == RoleEndorsement && entry.Format == AMDCRLV1Format:
			v, err := decodeAMDCRL(entry)
			if err != nil {
				return set, err
			}
			if cpu && set.CPU.AMDCRL == nil {
				set.CPU.AMDCRL = v
			}
		case entry.Role == RoleEndorsement && entry.Format == IntelPCSV1Format:
			v, err := decodeIntelPCS(entry)
			if err != nil {
				return set, err
			}
			if cpu && set.CPU.IntelPCS == nil {
				set.CPU.IntelPCS = v
			}
		case entry.Role == RoleReferenceValues && entry.Format == SigstoreCodeV1Format:
			v, err := decodeSigstoreRef(entry)
			if err != nil {
				return set, err
			}
			if set.SigstoreCode == nil {
				set.SigstoreCode = v
			}
		case entry.Role == RoleReferenceValues && entry.Format == SigstorePlatformV1Format:
			v, err := decodeSigstoreRef(entry)
			if err != nil {
				return set, err
			}
			if set.SigstorePlatform == nil {
				set.SigstorePlatform = v
			}
			if entry.ID == PlatformID {
				set.configPlatform = v
			}
		case entry.Role == RoleReferenceValues && entry.Format == SigstoreFreshnessV1Format:
			f, err := decodeFreshness(entry)
			if err != nil {
				return set, err
			}
			// validate already rejected duplicate IDs.
			set.Freshness[entry.ID] = f
		}
	}
	return set, nil
}

func validate(entries []Entry) error {
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
		// Only known formats are decoded, so every entry's data is checked
		// here: exactly one valid JSON object, with the strictness Parse
		// applies to the document (RFC 7493).
		if !entry.Data.IsValid() || entry.Data.Kind() != '{' {
			return fmt.Errorf("collateral entry %q data is not a valid JSON object", entry.ID)
		}
	}
	return nil
}

func unmarshalData(entry *Entry, label string, v any) error {
	if err := json.Unmarshal(entry.Data, v, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("parsing %s collateral entry %q: %w", label, entry.ID, err)
	}
	return nil
}

// CPUEndorsements is the decoded vendor collateral that chains CPU evidence to
// its vendor root. A nil field means no such collateral; which fields are
// required depends on the evidence format, and CPU-evidence authentication
// rejects evidence missing one.
type CPUEndorsements struct {
	AMDVCEK  *AMDVCEK
	AMDCRL   *AMDCRL
	IntelPCS *IntelPCS
}

// Clone returns a deep copy of e.
func (e CPUEndorsements) Clone() CPUEndorsements {
	return CPUEndorsements{AMDVCEK: e.AMDVCEK.Clone(), AMDCRL: e.AMDCRL.Clone(), IntelPCS: e.IntelPCS.Clone()}
}
