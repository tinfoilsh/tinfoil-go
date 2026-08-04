// Package policy parses the Sigstore-signed platform-endorsements artifact
// (predicate https://tinfoil.sh/predicate/platform-endorsements/v1) and turns
// its appraisal policies into enforceable validation options.
//
// The artifact maps hardware identifiers to named policies:
//   - AMD SEV-SNP machines are keyed by the 64-byte CHIP_ID report field
//     (128 lowercase hex chars; Turin hardware IDs are zero-padded)
//   - Intel TDX machines are keyed by the 16-byte PPID (32 lowercase hex
//     chars) carried in the PCK leaf certificate of every quote
//
// Parsing is fail-closed: unknown JSON fields, malformed identifiers,
// dangling policy references, or platform mismatches are errors. A policy
// that cannot be fully enforced must never be partially applied.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// ArtifactFormat is the required format URI of the platform-endorsements artifact.
const ArtifactFormat = "https://tinfoil.sh/predicate/platform-endorsements/v1"

const (
	// PlatformSEVSNP labels AMD SEV-SNP policies.
	PlatformSEVSNP = "sev-snp"
	// PlatformTDX labels Intel TDX policies.
	PlatformTDX = "tdx"

	sevIdentifierHexLen = 128
	tdxIdentifierHexLen = 32
)

var lowerHexRE = regexp.MustCompile(`^[0-9a-f]+$`)

// Artifact is the parsed platform-endorsements document.
type Artifact struct {
	Format       string                         `json:"format"`
	Measurements map[string]PlatformMeasurement `json:"measurements"`
	Machines     map[string]string              `json:"machines"`
	Policies     map[string]Policy              `json:"policies"`
}

// PlatformMeasurement is one TDX platform configuration's expected registers.
type PlatformMeasurement struct {
	MRTD  string        `json:"mrtd"`
	RTMR0 string        `json:"rtmr0"`
	Shape *MachineShape `json:"shape,omitempty"`
}

// MachineShape describes the VM resources bound to a platform measurement.
type MachineShape struct {
	CPUs     uint32 `json:"cpus"`
	Disks    uint32 `json:"disks"`
	MemoryMB uint32 `json:"memory_mb"`
}

// Policy is a named appraisal policy. Exactly one platform block is set,
// matching Platform.
type Policy struct {
	Platform string        `json:"platform"`
	SEVSNP   *SEVSNPPolicy `json:"sev_snp,omitempty"`
	TDX      *TDXPolicy    `json:"tdx,omitempty"`
}

// SEVSNPPolicy is the standard SEV-SNP policy block.
type SEVSNPPolicy struct {
	FamilyID                       string      `json:"family_id"`
	HostData                       string      `json:"host_data"`
	ImageID                        string      `json:"image_id"`
	MinimumABIVersion              string      `json:"minimum_abi_version"`
	MinimumBuild                   uint8       `json:"minimum_build"`
	MinimumAPIVersion              string      `json:"minimum_api_version"`
	MinimumCurrentMitigationVector uint64      `json:"minimum_current_mitigation_vector"`
	MinimumGuestSVN                uint32      `json:"minimum_guest_svn"`
	MinimumLaunchMitigationVector  uint64      `json:"minimum_launch_mitigation_vector"`
	MinimumTCB                     TCB         `json:"minimum_tcb"`
	MinimumLaunchTCB               TCB         `json:"minimum_launch_tcb"`
	GuestPolicy                    GuestPolicy `json:"guest_policy"`
	PlatformInfo                   SNPPlatform `json:"platform_info"`
	PermitProvisionalFirmware      bool        `json:"permit_provisional_firmware"`
	VMPL                           *int        `json:"vmpl"`
}

// TCB holds AMD security patch levels. FmcSpl applies to family 1Ah (Turin)
// parts only, which are not yet supported for verification.
type TCB struct {
	FmcSpl   *uint8 `json:"fmc_spl,omitempty"`
	BlSpl    uint8  `json:"bl_spl"`
	TeeSpl   uint8  `json:"tee_spl"`
	SnpSpl   uint8  `json:"snp_spl"`
	UcodeSpl uint8  `json:"ucode_spl"`
}

// GuestPolicy mirrors the SNP guest policy bits enforced at verification.
type GuestPolicy struct {
	Debug        bool `json:"debug"`
	SMT          bool `json:"smt"`
	MigrateMA    bool `json:"migrate_ma"`
	SingleSocket bool `json:"single_socket"`
}

// SNPPlatform mirrors the SNP PLATFORM_INFO expectations.
type SNPPlatform struct {
	AliasCheckComplete   bool `json:"alias_check_complete"`
	SMTEnabled           bool `json:"smt_enabled"`
	TSMEEnabled          bool `json:"tsme_enabled"`
	ECCEnabled           bool `json:"ecc_enabled"`
	RAPLDisabled         bool `json:"rapl_disabled"`
	CiphertextHidingDRAM bool `json:"ciphertext_hiding_dram"`
}

// TDXPolicy is the standard Intel TDX policy block.
type TDXPolicy struct {
	QEVendorID                     string   `json:"qe_vendor_id"`
	MinimumQESVN                   uint16   `json:"minimum_qe_svn"`
	MinimumPCESVN                  uint16   `json:"minimum_pce_svn"`
	MinimumTEETCBSVN               string   `json:"minimum_tee_tcb_svn"`
	AcceptedMRSeams                []string `json:"accepted_mr_seams"`
	MRSeam                         string   `json:"mr_seam"`
	TDAttributes                   string   `json:"td_attributes"`
	XFAM                           string   `json:"xfam"`
	MRConfigIDZero                 bool     `json:"mr_config_id_zero"`
	MROwnerZero                    bool     `json:"mr_owner_zero"`
	MROwnerConfigZero              bool     `json:"mr_owner_config_zero"`
	MinimumTCBEvaluationDataNumber int      `json:"minimum_tcb_evaluation_data_number"`
	PlatformMeasurements           []string `json:"platform_measurements"`
}

// ParseArtifact strictly decodes and validates a platform-endorsements
// artifact. Unknown fields anywhere in the document are rejected. Duplicate
// JSON member names are not detected; rejecting them is the publisher's
// responsibility.
func ParseArtifact(data []byte) (*Artifact, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var a Artifact
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("parsing platform-endorsements artifact: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after platform-endorsements artifact")
	}
	if a.Format != ArtifactFormat {
		return nil, fmt.Errorf("unsupported artifact format %q", a.Format)
	}
	for name, endorsementPolicy := range a.Policies {
		if endorsementPolicy.TDX == nil || endorsementPolicy.TDX.MRSeam == "" {
			continue
		}
		if len(endorsementPolicy.TDX.AcceptedMRSeams) != 0 {
			return nil, fmt.Errorf("policy %q: mr_seam and accepted_mr_seams are mutually exclusive", name)
		}
		endorsementPolicy.TDX.AcceptedMRSeams = []string{endorsementPolicy.TDX.MRSeam}
		a.Policies[name] = endorsementPolicy
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *Artifact) validate() error {
	for name, p := range a.Policies {
		switch p.Platform {
		case PlatformSEVSNP:
			if p.SEVSNP == nil || p.TDX != nil {
				return fmt.Errorf("policy %q: platform sev-snp requires exactly the sev_snp block", name)
			}
		case PlatformTDX:
			if p.TDX == nil || p.SEVSNP != nil {
				return fmt.Errorf("policy %q: platform tdx requires exactly the tdx block", name)
			}
			if p.TDX.MinimumTCBEvaluationDataNumber < 0 {
				return fmt.Errorf("policy %q: minimum_tcb_evaluation_data_number must not be negative", name)
			}
			for _, ref := range p.TDX.PlatformMeasurements {
				if _, ok := a.Measurements[ref]; !ok {
					return fmt.Errorf("policy %q: platform_measurements ref %q not in measurements", name, ref)
				}
			}
		default:
			return fmt.Errorf("policy %q: unsupported platform %q", name, p.Platform)
		}
	}

	for identifier, policyName := range a.Machines {
		p, ok := a.Policies[policyName]
		if !ok {
			return fmt.Errorf("machine %s...: unknown policy %q", truncID(identifier), policyName)
		}
		if !lowerHexRE.MatchString(identifier) {
			return fmt.Errorf("machine %s...: identifier is not lowercase hex", truncID(identifier))
		}
		switch p.Platform {
		case PlatformSEVSNP:
			if len(identifier) != sevIdentifierHexLen {
				return fmt.Errorf("machine %s...: sev-snp identifier must be %d hex chars, got %d",
					truncID(identifier), sevIdentifierHexLen, len(identifier))
			}
		case PlatformTDX:
			if len(identifier) != tdxIdentifierHexLen {
				return fmt.Errorf("machine %s...: tdx identifier must be %d hex chars, got %d",
					truncID(identifier), tdxIdentifierHexLen, len(identifier))
			}
		}
	}
	return nil
}

// PolicyFor looks up the appraisal policy for an authenticated platform
// identifier (lowercase hex) extracted from verified evidence, and asserts
// the policy's platform matches the evidence platform. An identifier absent
// from the machines map is an error: the machine is not endorsed.
func (a *Artifact) PolicyFor(identifierHex string, platform string) (string, *Policy, error) {
	name, ok := a.Machines[identifierHex]
	if !ok {
		return "", nil, fmt.Errorf("platform identifier %s... is not endorsed", truncID(identifierHex))
	}
	p := a.Policies[name]
	if p.Platform != platform {
		return "", nil, fmt.Errorf("policy %q is for platform %q, evidence is %q", name, p.Platform, platform)
	}
	return name, &p, nil
}

func truncID(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}
