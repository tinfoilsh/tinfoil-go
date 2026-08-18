package attestation

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/go-sev-guest/validate"
	"github.com/tinfoilsh/go-sev-guest/verify"
	"github.com/tinfoilsh/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

//go:generate sh -xc "curl -o genoa_cert_chain.pem https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
//go:embed genoa_cert_chain.pem
var vcekGenoaCertChain []byte

type getter struct{}

func (*getter) Get(targetURL string) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	if strings.HasSuffix(u.Path, "/cert_chain") {
		switch u.Path {
		case "/vcek/v1/Genoa/cert_chain":
			return vcekGenoaCertChain, nil
		case "/vcek/v1/Turin/cert_chain":
			return trust.AskArkTurinVcekBytes, nil
		}
		return nil, fmt.Errorf("cert_chain is not supported")
	}

	u.Host = "kds-proxy.tinfoil.sh"
	body, _, err := util.Get(u.String())
	if err != nil {
		return nil, err
	}
	return body, nil
}

var (
	_ trust.HTTPSGetter = &getter{}
)

// sevProductFromReport derives the SEV product from the report's CPUID
// family/model/stepping field (present in report version 3+). Reports
// without the field (version 2) predate Turin and are treated as Genoa.
func sevProductFromReport(report *sevsnp.Report) *sevsnp.SevProduct {
	if fms := report.GetCpuid1EaxFms(); fms != 0 {
		return abi.SevProductFromCpuid1Eax(fms)
	}
	return &sevsnp.SevProduct{
		Name:            sevsnp.SevProduct_SEV_PRODUCT_GENOA,
		MachineStepping: &wrapperspb.UInt32Value{Value: uint32(0)},
	}
}

// verifySevSignature decodes a report, derives its product, and verifies the
// report signature under the AMD roots (VCEK provided or fetched from KDS).
// It performs no policy validation; callers must validate the returned
// attestation before trusting any report field.
func verifySevSignature(attestationDoc string, isCompressed bool, vcekDER []byte) (*sevsnp.Attestation, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, err
	}

	if isCompressed {
		attDocBytes, err = gzipDecompress(attDocBytes)
		if err != nil {
			return nil, err
		}
	}

	parsedReport, err := abi.ReportToProto(attDocBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	opts := verify.DefaultOptions()
	opts.Getter = &getter{}
	opts.Product = sevProductFromReport(parsedReport)

	var attestation *sevsnp.Attestation
	if vcekDER != nil {
		// Use pre-provided VCEK certificate
		attestation = &sevsnp.Attestation{
			Report: parsedReport,
			CertificateChain: &sevsnp.CertificateChain{
				VcekCert: vcekDER,
			},
			Product: opts.Product,
		}
	} else {
		// Fetch VCEK from AMD KDS
		attestation, err = verify.GetAttestationFromReport(parsedReport, opts)
		if err != nil {
			return nil, fmt.Errorf("could not recreate attestation from report: %w", err)
		}
	}

	if err := verify.SnpAttestation(attestation, opts); err != nil {
		return nil, err
	}
	return attestation, nil
}

// verifySevReportWithEndorsements verifies a report signature, extracts the
// authenticated platform identity, looks up the machine's endorsed policy in
// the platform-endorsements artifact, and validates the report against that
// policy. Returns the verified report and the matched policy name. A machine
// absent from the artifact fails verification.
//
// The launch measurement (report.Measurement) is intentionally NOT checked
// here — it attests the workload, not the platform, and is not part of the
// endorsement policy. Callers MUST compare it against the expected code
// measurement, exactly as with verifySevReport.
func verifySevReportWithEndorsements(attestationDoc string, isCompressed bool, vcekDER []byte, endorsements *policy.Artifact) (*sevsnp.Report, string, error) {
	attestation, err := verifySevSignature(attestationDoc, isCompressed, vcekDER)
	if err != nil {
		return nil, "", err
	}
	report := attestation.GetReport()

	identity, err := policy.SEVIdentity(report.GetChipId())
	if err != nil {
		return nil, "", err
	}
	policyName, machinePolicy, err := endorsements.PolicyFor(identity, policy.PlatformSEVSNP)
	if err != nil {
		return nil, "", err
	}

	productLine := kds.ProductLine(sevProductFromReport(report))
	valOpts, err := machinePolicy.SEVSNP.SEVOptions(productLine)
	if err != nil {
		return nil, "", err
	}
	if err := validate.SnpAttestation(attestation, valOpts); err != nil {
		return nil, "", err
	}

	return report, policyName, nil
}

func verifySevReport(attestationDoc string, isCompressed bool, vcekDER []byte) (*sevsnp.Report, error) {
	attestation, err := verifySevSignature(attestationDoc, isCompressed, vcekDER)
	if err != nil {
		return nil, err
	}
	productLine := kds.ProductLine(sevProductFromReport(attestation.GetReport()))
	valOpts, err := defaultSEVOptions(productLine)
	if err != nil {
		return nil, err
	}

	if err := validate.SnpAttestation(attestation, valOpts); err != nil {
		return nil, err
	}

	return attestation.GetReport(), nil
}

func defaultSEVOptions(productLine string) (*validate.Options, error) {
	sevPolicy := &policy.SEVSNPPolicy{
		MinimumGuestSVN: 0,
		GuestPolicy: policy.GuestPolicy{
			SMT:          true,
			MigrateMA:    false,
			Debug:        false,
			SingleSocket: false,
		},
		PlatformInfo: policy.SNPPlatform{
			SMTEnabled:           true,
			TSMEEnabled:          true,
			ECCEnabled:           false,
			RAPLDisabled:         false,
			CiphertextHidingDRAM: false,
			AliasCheckComplete:   false,
		},
		PermitProvisionalFirmware: false,
	}

	switch productLine {
	case policy.ProductGenoa:
		sevPolicy.MinimumBuild = 21
		sevPolicy.MinimumAPIVersion = "1.55"
		sevPolicy.MinimumTCB = policy.TCB{BlSpl: 7, TeeSpl: 0, SnpSpl: 14, UcodeSpl: 72}
		sevPolicy.MinimumLaunchTCB = sevPolicy.MinimumTCB
	case policy.ProductTurin:
		fmcSpl := uint8(1)
		sevPolicy.MinimumBuild = 0
		sevPolicy.MinimumAPIVersion = "1.58"
		sevPolicy.MinimumTCB = policy.TCB{FmcSpl: &fmcSpl, BlSpl: 1, TeeSpl: 1, SnpSpl: 4, UcodeSpl: 82}
		sevPolicy.MinimumLaunchTCB = sevPolicy.MinimumTCB
	default:
		return nil, fmt.Errorf("unsupported SEV product line %q", productLine)
	}
	return sevPolicy.SEVOptions(productLine)
}

func verifySevAttestationV2(attestationDoc string) (*Verification, error) {
	return verifySevAttestationV2WithVCEK(attestationDoc, nil)
}

func verifySevAttestationV2WithVCEK(attestationDoc string, vcekDER []byte) (*Verification, error) {
	report, err := verifySevReport(attestationDoc, true, vcekDER)
	if err != nil {
		return nil, err
	}

	measurement := &Measurement{
		Type: SevGuestV2,
		Registers: []string{
			hex.EncodeToString(report.Measurement),
		},
	}
	return newVerificationV2(measurement, report.ReportData), nil
}
