package sev

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevvalidate "github.com/google/go-sev-guest/validate"

	"github.com/tinfoilsh/tinfoil-go/verifier/endorsement"
)

// ProductGenoa is the only AMD product line currently supported by the
// verifier. Turin (family 1Ah) is not supported yet.
const ProductGenoa = "Genoa"

// Expectations is the fully translated SEV-SNP expected state, resolved at
// policy assembly so that validation performs no translation and no
// artifact lookups.
type Expectations struct {
	opts *sevvalidate.Options
	// wantGuestPolicy and wantPlatformInfo are compared by strict equality:
	// the library only bounds them.
	wantGuestPolicy  sevabi.SnpPolicy
	wantPlatformInfo sevabi.SnpPlatformInfo
}

// Assemble translates an endorsed policy block into the complete expected
// state for a quote: go-sev-guest validation options carrying every policy
// field, the expected launch measurement from code provenance, and the
// expected REPORT_DATA from the envelope. Only Genoa (family 19h) is
// supported.
func Assemble(p *endorsement.SEVSNPPolicy, productLine string, launchDigest []byte, reportData [64]byte) (*Expectations, error) {
	opts, err := options(p, productLine)
	if err != nil {
		return nil, err
	}
	if len(launchDigest) != 48 {
		return nil, fmt.Errorf("expected launch digest must be 48 bytes, got %d", len(launchDigest))
	}
	opts.Measurement = launchDigest
	opts.ReportData = reportData[:]
	return &Expectations{
		opts:             opts,
		wantGuestPolicy:  expectedGuestPolicy(p),
		wantPlatformInfo: expectedPlatformInfo(p),
	}, nil
}

// Validate compares a signature-verified quote against the assembled
// expected state: the library validation options plus strict equality on
// the guest policy bits and PLATFORM_INFO, which the library only treats as
// maximum-acceptable masks. It is the only SEV policy enforcement entry
// point so that no subset of the policy can be applied.
func (e *Expectations) Validate(q *Quote) error {
	if err := sevvalidate.SnpAttestation(q.attestation, e.opts); err != nil {
		return err
	}

	report := q.attestation.GetReport()
	gotPolicy, err := sevabi.ParseSnpPolicy(report.GetPolicy())
	if err != nil {
		return fmt.Errorf("parsing report guest policy: %w", err)
	}
	wantPolicy := e.wantGuestPolicy
	// ABI major/minor are version floors covered by the options, not bits.
	wantPolicy.ABIMajor = gotPolicy.ABIMajor
	wantPolicy.ABIMinor = gotPolicy.ABIMinor
	if gotPolicy != wantPolicy {
		return fmt.Errorf("report guest policy %+v does not equal the endorsed policy %+v", gotPolicy, wantPolicy)
	}

	gotInfo, err := sevabi.ParseSnpPlatformInfo(report.GetPlatformInfo())
	if err != nil {
		return fmt.Errorf("parsing report PLATFORM_INFO: %w", err)
	}
	if gotInfo != e.wantPlatformInfo {
		return fmt.Errorf("report PLATFORM_INFO %+v does not equal the endorsed policy %+v", gotInfo, e.wantPlatformInfo)
	}
	return nil
}

// ProductLine returns the product line of an authenticated quote, used to
// select the policy translation.
func (q *Quote) ProductLine() string {
	return kds.ProductLine(q.attestation.GetProduct())
}

// expectedGuestPolicy returns the guest policy bits the report must carry.
func expectedGuestPolicy(p *endorsement.SEVSNPPolicy) sevabi.SnpPolicy {
	return sevabi.SnpPolicy{
		Debug:                p.GuestPolicy.Debug,
		SMT:                  p.GuestPolicy.SMT,
		MigrateMA:            p.GuestPolicy.MigrateMA,
		SingleSocket:         p.GuestPolicy.SingleSocket,
		CXLAllowed:           p.GuestPolicy.CXLAllowed,
		MemAES256XTS:         p.GuestPolicy.MemAES256XTS,
		RAPLDis:              p.GuestPolicy.RAPLDis,
		CipherTextHidingDRAM: p.GuestPolicy.CiphertextHidingDRAM,
		PageSwapDisable:      p.GuestPolicy.PageSwapDisable,
	}
}

// expectedPlatformInfo returns the PLATFORM_INFO the report must carry.
func expectedPlatformInfo(p *endorsement.SEVSNPPolicy) sevabi.SnpPlatformInfo {
	return sevabi.SnpPlatformInfo{
		SMTEnabled:                  p.PlatformInfo.SMTEnabled,
		TSMEEnabled:                 p.PlatformInfo.TSMEEnabled,
		ECCEnabled:                  p.PlatformInfo.ECCEnabled,
		RAPLDisabled:                p.PlatformInfo.RAPLDisabled,
		CiphertextHidingDRAMEnabled: p.PlatformInfo.CiphertextHidingDRAM,
		AliasCheckComplete:          p.PlatformInfo.AliasCheckComplete,
		TIOEnabled:                  p.PlatformInfo.TIOEnabled,
	}
}

// options translates the policy block into go-sev-guest validation options
// for the given product line. The library treats GuestPolicy and
// PlatformInfo as maximum-acceptable masks; strict equality on both is
// enforced by the companion checks composed in Validate.
func options(p *endorsement.SEVSNPPolicy, productLine string) (*sevvalidate.Options, error) {
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
	hostData, err := optionalHexField("host_data", p.HostData, 32)
	if err != nil {
		return nil, err
	}
	imageID, err := optionalHexField("image_id", p.ImageID, 16)
	if err != nil {
		return nil, err
	}
	familyID, err := optionalHexField("family_id", p.FamilyID, 16)
	if err != nil {
		return nil, err
	}

	platformInfo := expectedPlatformInfo(p)
	return &sevvalidate.Options{
		GuestPolicy:               expectedGuestPolicy(p),
		MinimumGuestSvn:           p.MinimumGuestSVN,
		MinimumBuild:              p.MinimumBuild,
		MinimumVersion:            version,
		PermitProvisionalFirmware: p.PermitProvisionalFirmware,
		PlatformInfo:              &platformInfo,
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
		VMPL:                           cloneIntPtr(p.VMPL),
		HostData:                       hostData,
		ImageID:                        imageID,
		FamilyID:                       familyID,
		RequireAuthorKey:               p.RequireAuthorKey,
		RequireIDBlock:                 p.RequireIDBlock,
		MinimumLaunchMitigationVector:  p.MinimumLaunchMitigationVector,
		MinimumCurrentMitigationVector: p.MinimumCurrentMitigationVector,
	}, nil
}

// cloneIntPtr copies an optional int so assembled expectations do not alias
// the policy struct they were translated from.
func cloneIntPtr(v *int) *int {
	if v == nil {
		return nil
	}
	c := *v
	return &c
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

// optionalHexField decodes an optional pinned hex field; nil stays nil
// (unchecked by the validation library).
func optionalHexField(name string, value *string, wantLen int) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	return hexField(name, *value, wantLen)
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
