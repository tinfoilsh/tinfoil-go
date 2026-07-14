package policy

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
