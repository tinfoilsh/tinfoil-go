// Package endorsement defines the schema of the Sigstore-signed
// platform-endorsements artifact (predicate
// https://tinfoil.sh/predicate/platform-endorsements/v1) and the
// authenticated lookups over it.
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
package endorsement

import (
	"fmt"
	"regexp"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/strictjson"
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

// PlatformMeasurement is one TDX platform configuration's expected registers,
// optionally annotated with the VM shape and host stack it was measured for.
type PlatformMeasurement struct {
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
	Shape *Shape `json:"shape,omitempty"`
	Stack *Stack `json:"stack,omitempty"`
}

// Shape is the canonical VM shape descriptor: the launch dimensions that
// determine a platform measurement. Disks counts every attached disk
// (root, config, external config, one per model). GPUs is nil when the
// dimension is unknown for a measured slug; a code artifact always
// declares it.
type Shape struct {
	CPUs     int  `json:"cpus"`
	MemoryMB int  `json:"memory_mb"`
	GPUs     *int `json:"gpus,omitempty"`
	Disks    int  `json:"disks"`
}

// Satisfies reports whether a measured slug shape satisfies the shape a
// code artifact requires. GPUs is compared only when the slug declares it.
func (s *Shape) Satisfies(required *Shape) bool {
	if s.CPUs != required.CPUs || s.MemoryMB != required.MemoryMB || s.Disks != required.Disks {
		return false
	}
	if s.GPUs != nil && required.GPUs != nil && *s.GPUs != *required.GPUs {
		return false
	}
	return true
}

// Stack identifies the host software that produced a measurement.
type Stack struct {
	QEMU string `json:"qemu,omitempty"`
	OVMF string `json:"ovmf,omitempty"`
}

// Policy is a named appraisal policy. Exactly one platform block is set,
// matching Platform.
type Policy struct {
	Platform string        `json:"platform"`
	SEVSNP   *SEVSNPPolicy `json:"sev_snp,omitempty"`
	TDX      *TDXPolicy    `json:"tdx,omitempty"`
}

// SEVSNPPolicy is the standard SEV-SNP policy block. Optional expected-value
// fields (host_data, image_id, family_id) are unchecked when absent.
type SEVSNPPolicy struct {
	MinimumBuild              uint8       `json:"minimum_build"`
	MinimumAPIVersion         string      `json:"minimum_api_version"`
	MinimumGuestSVN           uint32      `json:"minimum_guest_svn"`
	MinimumTCB                TCB         `json:"minimum_tcb"`
	MinimumLaunchTCB          TCB         `json:"minimum_launch_tcb"`
	GuestPolicy               GuestPolicy `json:"guest_policy"`
	PlatformInfo              SNPPlatform `json:"platform_info"`
	PermitProvisionalFirmware bool        `json:"permit_provisional_firmware"`
	VMPL                      *int        `json:"vmpl"`

	// HostData pins the report HOST_DATA field (32 bytes, lowercase hex).
	HostData *string `json:"host_data,omitempty"`
	// ImageID pins the report IMAGE_ID field (16 bytes, lowercase hex).
	ImageID *string `json:"image_id,omitempty"`
	// FamilyID pins the report FAMILY_ID field (16 bytes, lowercase hex).
	FamilyID *string `json:"family_id,omitempty"`
	// RequireAuthorKey requires AUTHOR_KEY_EN=1 (implies RequireIDBlock).
	RequireAuthorKey bool `json:"require_author_key,omitempty"`
	// RequireIDBlock requires a trusted ID block signature chain.
	RequireIDBlock bool `json:"require_id_block,omitempty"`
	// MinimumLaunchMitigationVector and MinimumCurrentMitigationVector are
	// the mitigation bits that must be present in the report.
	MinimumLaunchMitigationVector  uint64 `json:"minimum_launch_mitigation_vector,omitempty"`
	MinimumCurrentMitigationVector uint64 `json:"minimum_current_mitigation_vector,omitempty"`
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
// All bits are compared: a bit absent from the policy JSON is false and the
// report must have it clear.
type GuestPolicy struct {
	Debug        bool `json:"debug"`
	SMT          bool `json:"smt"`
	MigrateMA    bool `json:"migrate_ma"`
	SingleSocket bool `json:"single_socket"`
	CXLAllowed   bool `json:"cxl_allowed,omitempty"`
	MemAES256XTS bool `json:"mem_aes256_xts,omitempty"`
	RAPLDis      bool `json:"rapl_dis,omitempty"`
	// CiphertextHidingDRAM here is the guest-policy bit, distinct from the
	// PLATFORM_INFO field of the same name.
	CiphertextHidingDRAM bool `json:"ciphertext_hiding_dram,omitempty"`
	PageSwapDisable      bool `json:"page_swap_disable,omitempty"`
}

// SNPPlatform mirrors the SNP PLATFORM_INFO expectations. All fields are
// compared by strict equality against the report, so machines with
// different host configurations need distinct policies.
type SNPPlatform struct {
	SMTEnabled           bool `json:"smt_enabled"`
	TSMEEnabled          bool `json:"tsme_enabled"`
	ECCEnabled           bool `json:"ecc_enabled"`
	RAPLDisabled         bool `json:"rapl_disabled"`
	CiphertextHidingDRAM bool `json:"ciphertext_hiding_dram"`
	AliasCheckComplete   bool `json:"alias_check_complete,omitempty"`
	TIOEnabled           bool `json:"tio_enabled,omitempty"`
}

// TDXPolicy is the standard Intel TDX policy block. PlatformMeasurements
// names the measurements-map entries the machine is endorsed to run; the
// quote's own MRTD/RTMR0 select exactly one of them at policy assembly.
type TDXPolicy struct {
	QEVendorID                     string   `json:"qe_vendor_id"`
	MinimumQESVN                   uint16   `json:"minimum_qe_svn"`
	MinimumPCESVN                  uint16   `json:"minimum_pce_svn"`
	MinimumTEETCBSVN               string   `json:"minimum_tee_tcb_svn"`
	MRSeam                         string   `json:"mr_seam"`
	TDAttributes                   string   `json:"td_attributes"`
	XFAM                           string   `json:"xfam"`
	MRConfigIDZero                 bool     `json:"mr_config_id_zero"`
	MROwnerZero                    bool     `json:"mr_owner_zero"`
	MROwnerConfigZero              bool     `json:"mr_owner_config_zero"`
	MinimumTCBEvaluationDataNumber int      `json:"minimum_tcb_evaluation_data_number"`
	PlatformMeasurements           []string `json:"platform_measurements"`
}

// Parse strictly decodes and validates a platform-endorsements
// artifact. Unknown members anywhere in the document are rejected
// case-sensitively, as are duplicate member names.
func Parse(data []byte) (*Artifact, error) {
	var a Artifact
	if err := strictjson.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing platform-endorsements artifact: %w", err)
	}
	if a.Format != ArtifactFormat {
		return nil, fmt.Errorf("unsupported artifact format %q", a.Format)
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

// ResolvePlatformMeasurement selects the single measurements-map entry the
// policy allows whose MRTD/RTMR0 equal the quote's authenticated values,
// returning its name. When required is non-nil, only entries measured for
// that VM shape are candidates, so a quote from a machine-endorsed but
// wrong-shaped VM resolves nothing. The measurement inputs must come from a
// verified quote.
func (a *Artifact) ResolvePlatformMeasurement(p *TDXPolicy, required *Shape, mrtdHex, rtmr0Hex string) (string, *PlatformMeasurement, error) {
	anyShapeMatch := false
	for _, ref := range p.PlatformMeasurements {
		m := a.Measurements[ref]
		if required != nil && (m.Shape == nil || !m.Shape.Satisfies(required)) {
			continue
		}
		anyShapeMatch = true
		if m.MRTD == mrtdHex && m.RTMR0 == rtmr0Hex {
			return ref, &m, nil
		}
	}
	if required != nil && !anyShapeMatch {
		return "", nil, fmt.Errorf("no endorsed platform measurement matches the required VM shape %+v", *required)
	}
	return "", nil, fmt.Errorf("platform measurements (mrtd %s...) do not match any allowed configuration", truncID(mrtdHex))
}
