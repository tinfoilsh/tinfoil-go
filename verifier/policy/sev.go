package policy

import "fmt"

// SEVSNPPolicy is the standard SEV-SNP policy block. Every field is
// required and checked; there are no unchecked report fields. Numeric
// members are pointers so parsing can tell an absent member from a
// meaningful zero — Validate rejects any absent member.
type SEVSNPPolicy struct {
	MinimumBuild                   *uint8      `json:"minimum_build"`
	MinimumAPIVersion              string      `json:"minimum_api_version"`
	MinimumGuestSVN                *uint32     `json:"minimum_guest_svn"`
	MinimumTCB                     TCB         `json:"minimum_tcb"`
	MinimumLaunchTCB               TCB         `json:"minimum_launch_tcb"`
	GuestPolicy                    GuestPolicy `json:"guest_policy"`
	PlatformInfo                   SNPPlatform `json:"platform_info"`
	PermitProvisionalFirmware      bool        `json:"permit_provisional_firmware"`
	VMPL                           *int        `json:"vmpl"`
	HostData                       string      `json:"host_data"`
	ImageID                        string      `json:"image_id"`
	FamilyID                       string      `json:"family_id"`
	RequireAuthorKey               bool        `json:"require_author_key,omitempty"`
	RequireIDBlock                 bool        `json:"require_id_block,omitempty"`
	MinimumLaunchMitigationVector  *uint64     `json:"minimum_launch_mitigation_vector"`
	MinimumCurrentMitigationVector *uint64     `json:"minimum_current_mitigation_vector"`
}

// Validate rejects a block with any absent required member or an
// unsupported setting.
func (p *SEVSNPPolicy) Validate() error {
	switch {
	case p.MinimumBuild == nil:
		return fmt.Errorf("minimum_build is required")
	case p.MinimumAPIVersion == "":
		return fmt.Errorf("minimum_api_version is required")
	case p.MinimumGuestSVN == nil:
		return fmt.Errorf("minimum_guest_svn is required")
	case p.VMPL == nil:
		return fmt.Errorf("vmpl is required")
	case *p.VMPL < 0 || *p.VMPL > 3:
		return fmt.Errorf("vmpl must be between 0 and 3")
	case p.HostData == "":
		return fmt.Errorf("host_data is required")
	case p.ImageID == "":
		return fmt.Errorf("image_id is required")
	case p.FamilyID == "":
		return fmt.Errorf("family_id is required")
	case p.MinimumLaunchMitigationVector == nil:
		return fmt.Errorf("minimum_launch_mitigation_vector is required")
	case p.MinimumCurrentMitigationVector == nil:
		return fmt.Errorf("minimum_current_mitigation_vector is required")
	case p.RequireAuthorKey || p.RequireIDBlock:
		return fmt.Errorf("require_author_key and require_id_block are not supported (no trusted key material is modeled)")
	}
	if err := p.MinimumTCB.validate(); err != nil {
		return fmt.Errorf("minimum_tcb: %w", err)
	}
	if err := p.MinimumLaunchTCB.validate(); err != nil {
		return fmt.Errorf("minimum_launch_tcb: %w", err)
	}
	return nil
}

// TCB holds AMD security patch levels. FmcSpl applies to family 1Ah (Turin)
// parts only, which are not yet supported for verification.
type TCB struct {
	FmcSpl   *uint8 `json:"fmc_spl,omitempty"`
	BlSpl    *uint8 `json:"bl_spl"`
	TeeSpl   *uint8 `json:"tee_spl"`
	SnpSpl   *uint8 `json:"snp_spl"`
	UcodeSpl *uint8 `json:"ucode_spl"`
}

func (t *TCB) validate() error {
	switch {
	case t.BlSpl == nil:
		return fmt.Errorf("bl_spl is required")
	case t.TeeSpl == nil:
		return fmt.Errorf("tee_spl is required")
	case t.SnpSpl == nil:
		return fmt.Errorf("snp_spl is required")
	case t.UcodeSpl == nil:
		return fmt.Errorf("ucode_spl is required")
	}
	return nil
}

// GuestPolicy mirrors the SNP guest policy bits enforced at verification.
// All bits are compared: a bit absent from the policy JSON is false and the
// report must have it clear.
type GuestPolicy struct {
	Debug                bool `json:"debug"`
	SMT                  bool `json:"smt"`
	MigrateMA            bool `json:"migrate_ma"`
	SingleSocket         bool `json:"single_socket"`
	CXLAllowed           bool `json:"cxl_allowed,omitempty"`
	MemAES256XTS         bool `json:"mem_aes256_xts,omitempty"`
	RAPLDis              bool `json:"rapl_dis,omitempty"`
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
