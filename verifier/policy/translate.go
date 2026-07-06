package policy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevvalidate "github.com/google/go-sev-guest/validate"
	tdxvalidate "github.com/google/go-tdx-guest/validate"
)

// ProductGenoa is the AMD product line supported by the v3 verifier. Turin
// (family 1Ah) is intentionally not supported yet (see MASTER_PLAN.md): its
// TCB_VERSION layout and VCEK HWID differ, and a firmware PLATFORM_INFO
// discrepancy on our Turin hardware is still under investigation with AMD.
const ProductGenoa = "Genoa"

// SEVOptions translates the policy block into go-sev-guest validation
// options for the given product line. Only Genoa (family 19h) is supported.
func (p *SEVSNPPolicy) SEVOptions(productLine string) (*sevvalidate.Options, error) {
	if productLine != ProductGenoa {
		return nil, fmt.Errorf("unsupported SEV product line %q (only %s is supported)", productLine, ProductGenoa)
	}
	version, err := parseAPIVersion(p.MinimumAPIVersion)
	if err != nil {
		return nil, err
	}
	if p.MinimumTCB.FmcSpl != nil || p.MinimumLaunchTCB.FmcSpl != nil {
		return nil, fmt.Errorf("fmc_spl is not valid for product line %s", productLine)
	}

	return &sevvalidate.Options{
		GuestPolicy: sevabi.SnpPolicy{
			Debug:        p.GuestPolicy.Debug,
			SMT:          p.GuestPolicy.SMT,
			MigrateMA:    p.GuestPolicy.MigrateMA,
			SingleSocket: p.GuestPolicy.SingleSocket,
		},
		MinimumGuestSvn:           p.MinimumGuestSVN,
		MinimumBuild:              p.MinimumBuild,
		MinimumVersion:            version,
		PermitProvisionalFirmware: p.PermitProvisionalFirmware,
		PlatformInfo: &sevabi.SnpPlatformInfo{
			SMTEnabled:                  p.PlatformInfo.SMTEnabled,
			TSMEEnabled:                 p.PlatformInfo.TSMEEnabled,
			ECCEnabled:                  p.PlatformInfo.ECCEnabled,
			RAPLDisabled:                p.PlatformInfo.RAPLDisabled,
			CiphertextHidingDRAMEnabled: p.PlatformInfo.CiphertextHidingDRAM,
		},
		MinimumTCB: kds.TCBParts{
			BlSpl:    p.MinimumTCB.BlSpl,
			TeeSpl:   p.MinimumTCB.TeeSpl,
			SnpSpl:   p.MinimumTCB.SnpSpl,
			UcodeSpl: p.MinimumTCB.UcodeSpl,
		},
		MinimumLaunchTCB: kds.TCBParts{
			BlSpl:    p.MinimumLaunchTCB.BlSpl,
			TeeSpl:   p.MinimumLaunchTCB.TeeSpl,
			SnpSpl:   p.MinimumLaunchTCB.SnpSpl,
			UcodeSpl: p.MinimumLaunchTCB.UcodeSpl,
		},
		VMPL: p.VMPL,
	}, nil
}

// TDXOptions translates the policy block into go-tdx-guest validation
// options. MR_SEAM membership, the TCB evaluation data number, and platform
// measurement matching are not expressible in the library options and are
// enforced by the companion methods below.
func (p *TDXPolicy) TDXOptions() (*tdxvalidate.Options, error) {
	qeVendor, err := hexField("qe_vendor_id", p.QEVendorID, 16)
	if err != nil {
		return nil, err
	}
	teeTcbSvn, err := hexField("minimum_tee_tcb_svn", p.MinimumTEETCBSVN, 16)
	if err != nil {
		return nil, err
	}
	tdAttributes, err := hexField("td_attributes", p.TDAttributes, 8)
	if err != nil {
		return nil, err
	}
	xfam, err := hexField("xfam", p.XFAM, 8)
	if err != nil {
		return nil, err
	}

	opts := &tdxvalidate.Options{
		HeaderOptions: tdxvalidate.HeaderOptions{
			MinimumQeSvn:  p.MinimumQESVN,
			MinimumPceSvn: p.MinimumPCESVN,
			QeVendorID:    qeVendor,
		},
		TdQuoteBodyOptions: tdxvalidate.TdQuoteBodyOptions{
			MinimumTeeTcbSvn: teeTcbSvn,
			TdAttributes:     tdAttributes,
			Xfam:             xfam,
		},
	}
	if p.MRConfigIDZero {
		opts.TdQuoteBodyOptions.MrConfigID = make([]byte, 48)
	}
	if p.MROwnerZero {
		opts.TdQuoteBodyOptions.MrOwner = make([]byte, 48)
	}
	if p.MROwnerConfigZero {
		opts.TdQuoteBodyOptions.MrOwnerConfig = make([]byte, 48)
	}
	return opts, nil
}

// CheckMRSeam verifies membership of the quote's MR_SEAM in the policy's
// accepted set.
func (p *TDXPolicy) CheckMRSeam(mrSeam []byte) error {
	for _, accepted := range p.AcceptedMRSeams {
		want, err := hex.DecodeString(accepted)
		if err != nil {
			return fmt.Errorf("policy accepted_mr_seams entry is not hex: %w", err)
		}
		if bytes.Equal(mrSeam, want) {
			return nil
		}
	}
	return fmt.Errorf("MR_SEAM %s is not in the policy's accepted set", hex.EncodeToString(mrSeam))
}

// CheckPlatformMeasurement verifies the quote's MRTD/RTMR0 against the
// platform measurements the policy allows, resolved through the artifact.
func (a *Artifact) CheckPlatformMeasurement(p *TDXPolicy, mrtdHex, rtmr0Hex string) error {
	for _, ref := range p.PlatformMeasurements {
		m := a.Measurements[ref]
		if m.MRTD == mrtdHex && m.RTMR0 == rtmr0Hex {
			return nil
		}
	}
	return fmt.Errorf("platform measurements (mrtd %s...) do not match any allowed configuration", truncID(mrtdHex))
}

func parseAPIVersion(v string) (uint16, error) {
	major, minor, found := strings.Cut(v, ".")
	if !found {
		return 0, fmt.Errorf("minimum_api_version %q is not maj.min", v)
	}
	maj, err := strconv.ParseUint(major, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("minimum_api_version major: %w", err)
	}
	min, err := strconv.ParseUint(minor, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("minimum_api_version minor: %w", err)
	}
	return uint16(maj<<8 | min), nil
}

func hexField(name, value string, wantLen int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", name, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", name, wantLen, len(b))
	}
	return b, nil
}
