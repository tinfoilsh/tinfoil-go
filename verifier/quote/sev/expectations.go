package sev

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevvalidate "github.com/google/go-sev-guest/validate"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// ProductGenoa is the only AMD product line currently supported by the
// verifier. Turin (family 1Ah) is not supported yet.
const ProductGenoa = "Genoa"

// Expectations is the fully translated SEV-SNP expected state, resolved at
// assembly so that validation performs no translation and no lookups. The
// want* fields are compared by strict equality — the library options only
// bound them.
type Expectations struct {
	opts             *sevvalidate.Options
	wantGuestPolicy  sevabi.SnpPolicy
	wantPlatformInfo sevabi.SnpPlatformInfo
}

// Assemble translates a policy block into the complete expected state for
// a quote: validation options carrying every policy field, the expected
// launch measurement, and the expected REPORT_DATA. Only Genoa is
// supported.
func Assemble(p *policy.SEVSNPPolicy, productLine string, launchDigest []byte, reportData [64]byte) (*Expectations, error) {
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

// Validate compares a quote against the assembled expected state: the
// library validation options plus the strict-equality companions. It is
// the only SEV enforcement entry point, so no subset of the policy can be
// applied.
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
	// ABI major/minor are a version floor (minimum_abi_version), enforced
	// by the library's guest-policy comparison, not exact bits.
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

	return e.checkSigner(report)
}

// checkSigner requires the report to be launched without an author key or
// ID block: ID-block launches are unsupported (policy parsing rejects
// require_* flags), and the library options cannot require absence.
func (e *Expectations) checkSigner(report *sevsnp.Report) error {
	signer, err := sevabi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return fmt.Errorf("parsing report SIGNER_INFO: %w", err)
	}
	if signer.AuthorKeyEn {
		return fmt.Errorf("report carries an author key; ID-block launches are unsupported")
	}
	if !bytes.Equal(report.GetIdKeyDigest(), make([]byte, len(report.GetIdKeyDigest()))) {
		return fmt.Errorf("report carries an ID block; ID-block launches are unsupported")
	}
	if !bytes.Equal(report.GetAuthorKeyDigest(), make([]byte, len(report.GetAuthorKeyDigest()))) {
		return fmt.Errorf("report carries an author key digest; ID-block launches are unsupported")
	}
	return nil
}

// ProductLine returns the product line of an authenticated quote, used to
// select the policy translation.
func (q *Quote) ProductLine() string {
	return kds.ProductLine(q.attestation.GetProduct())
}

func expectedGuestPolicy(p *policy.SEVSNPPolicy) sevabi.SnpPolicy {
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

func expectedPlatformInfo(p *policy.SEVSNPPolicy) sevabi.SnpPlatformInfo {
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
func options(p *policy.SEVSNPPolicy, productLine string) (*sevvalidate.Options, error) {
	if productLine != ProductGenoa {
		return nil, fmt.Errorf("unsupported SEV product line %q (only %s is supported)", productLine, ProductGenoa)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	version, err := parseVersion("minimum_api_version", p.MinimumAPIVersion)
	if err != nil {
		return nil, err
	}
	abiMajor, abiMinor, err := parseVersionParts("minimum_abi_version", p.MinimumABIVersion)
	if err != nil {
		return nil, err
	}
	if p.MinimumTCB.FmcSpl != nil || p.MinimumLaunchTCB.FmcSpl != nil {
		return nil, fmt.Errorf("fmc_spl is not valid for product line %s", productLine)
	}
	// Snapshot so the assembled expectations do not alias the policy.
	vmpl := *p.VMPL
	hostData, err := policy.DecodeHex("host_data", p.HostData, 32)
	if err != nil {
		return nil, err
	}
	imageID, err := policy.DecodeHex("image_id", p.ImageID, 16)
	if err != nil {
		return nil, err
	}
	familyID, err := policy.DecodeHex("family_id", p.FamilyID, 16)
	if err != nil {
		return nil, err
	}

	// The ABI floor rides in the guest policy: the library compares it as
	// a minimum version, unlike the other bits.
	guestPolicy := expectedGuestPolicy(p)
	guestPolicy.ABIMajor = abiMajor
	guestPolicy.ABIMinor = abiMinor
	platformInfo := expectedPlatformInfo(p)
	return &sevvalidate.Options{
		GuestPolicy:                    guestPolicy,
		MinimumGuestSvn:                *p.MinimumGuestSVN,
		MinimumBuild:                   *p.MinimumBuild,
		MinimumVersion:                 version,
		PermitProvisionalFirmware:      p.PermitProvisionalFirmware,
		PlatformInfo:                   &platformInfo,
		MinimumTCB:                     tcbParts(p.MinimumTCB),
		MinimumLaunchTCB:               tcbParts(p.MinimumLaunchTCB),
		VMPL:                           &vmpl,
		HostData:                       hostData,
		ImageID:                        imageID,
		FamilyID:                       familyID,
		MinimumLaunchMitigationVector:  *p.MinimumLaunchMitigationVector,
		MinimumCurrentMitigationVector: *p.MinimumCurrentMitigationVector,
	}, nil
}

func tcbParts(t policy.TCB) kds.TCBParts {
	return kds.TCBParts{
		BlSpl:    *t.BlSpl,
		TeeSpl:   *t.TeeSpl,
		SnpSpl:   *t.SnpSpl,
		UcodeSpl: *t.UcodeSpl,
	}
}

func parseVersion(name, v string) (uint16, error) {
	maj, min, err := parseVersionParts(name, v)
	if err != nil {
		return 0, err
	}
	return uint16(maj)<<8 | uint16(min), nil
}

func parseVersionParts(name, v string) (uint8, uint8, error) {
	major, minor, found := strings.Cut(v, ".")
	if !found {
		return 0, 0, fmt.Errorf("%s %q is not maj.min", name, v)
	}
	maj, err := strconv.ParseUint(major, 10, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("%s major: %w", name, err)
	}
	min, err := strconv.ParseUint(minor, 10, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("%s minor: %w", name, err)
	}
	return uint8(maj), uint8(min), nil
}
