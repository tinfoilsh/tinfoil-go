// Package sev authenticates AMD SEV-SNP reports against the pinned AMD
// roots and assembles complete go-sev-guest validation options from an
// endorsed policy.
package sev

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/strictjson"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

//go:generate sh -xc "curl -o genoa_cert_chain.pem https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
//go:embed genoa_cert_chain.pem
var vcekGenoaCertChain []byte

// offlineGetter serves SEV verification fetches from pre-provided material:
// the CRL from document collateral and the cert chain from the embedded
// copy. Everything else fails — no network.
type offlineGetter struct {
	crlDER []byte
}

func (g *offlineGetter) Get(targetURL string) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	switch {
	case strings.HasSuffix(u.Path, "/crl") && g.crlDER != nil:
		return g.crlDER, nil
	case u.Path == "/vcek/v1/Genoa/cert_chain":
		return vcekGenoaCertChain, nil
	}
	return nil, fmt.Errorf("offline verification cannot fetch %s", targetURL)
}

// productFromReport derives the SEV product from the report's CPUID
// family/model/stepping field (present in report version 3+). Reports
// without the field (version 2) predate Turin and are treated as Genoa.
func productFromReport(report *sevsnp.Report) *sevsnp.SevProduct {
	if fms := report.GetCpuid1EaxFms(); fms != 0 {
		return abi.SevProductFromCpuid1Eax(fms)
	}
	return &sevsnp.SevProduct{
		Name:            sevsnp.SevProduct_SEV_PRODUCT_GENOA,
		MachineStepping: &wrapperspb.UInt32Value{Value: uint32(0)},
	}
}

// Quote is an authenticated SEV-SNP report: the signature chain up to the
// pinned AMD root has been verified. Nothing in it has been compared
// against expected values yet.
type Quote struct {
	// Identity is the machines-map lookup key (CHIP_ID, lowercase hex).
	Identity string
	// Measurement is the launch measurement register.
	Measurement *measurement.Measurement

	attestation *sevsnp.Attestation
}

// Attestation returns the verified attestation for policy assembly.
func (q *Quote) Attestation() *sevsnp.Attestation { return q.attestation }

// Authenticate verifies a v3 document's SEV-SNP report: signature chain up
// to the pinned AMD root, using the VCEK carried in the document's own
// collateral — single-request, no network fetches. When the document
// carries an amd-crl collateral entry, VCEK revocation is checked against
// it. It makes no reference-value comparison; callers must assemble a
// policy and validate before trusting the platform.
func Authenticate(doc *envelope.Document) (*Quote, error) {
	// The VCEK comes from the document's own collateral; its chain is
	// verified against the pinned AMD root, so the entry is untrusted input.
	entry, ok := doc.EndorsementCollateral(envelope.CollateralAMDVCEKV1Format, envelope.SubjectCPU)
	if !ok {
		return nil, fmt.Errorf("document carries no amd-vcek endorsement collateral for the cpu")
	}
	var data envelope.AMDVCEKCollateral
	if err := strictjson.Unmarshal(entry.Data, &data); err != nil {
		return nil, fmt.Errorf("parsing amd-vcek collateral entry %q: %w", entry.ID, err)
	}
	vcekDER, err := base64.StdEncoding.DecodeString(data.VCEKDERBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding vcek_der_base64: %w", err)
	}
	// An empty VCEK would make the library try to fetch one; reject it
	// before verification so the failure is explicit (and offline).
	if len(vcekDER) == 0 {
		return nil, fmt.Errorf("amd-vcek collateral entry %q carries an empty VCEK", entry.ID)
	}

	// VCEK revocation is checked against the CRL when the document carries
	// one; documents predating the amd-crl entry verify without it.
	var crlDER []byte
	if crlEntry, ok := doc.EndorsementCollateral(envelope.CollateralAMDCRLV1Format, envelope.SubjectCPU); ok {
		var crl envelope.AMDCRLCollateral
		if err := strictjson.Unmarshal(crlEntry.Data, &crl); err != nil {
			return nil, fmt.Errorf("parsing amd-crl collateral entry %q: %w", crlEntry.ID, err)
		}
		crlDER, err = base64.StdEncoding.DecodeString(crl.CRLDERBase64)
		if err != nil {
			return nil, fmt.Errorf("decoding crl_der_base64: %w", err)
		}
	}

	att, err := verifySignature(doc.CPUEvidence.ReportBase64, vcekDER, crlDER)
	if err != nil {
		return nil, err
	}
	report := att.GetReport()

	identity, err := Identity(report.GetChipId())
	if err != nil {
		return nil, err
	}

	return &Quote{
		Identity: identity,
		Measurement: &measurement.Measurement{
			Type:      measurement.SevGuestV2,
			Registers: []string{hex.EncodeToString(report.Measurement)},
		},
		attestation: att,
	}, nil
}

// verifySignature decodes a report, derives its product, and verifies the
// report signature under the AMD roots using the provided VCEK. When crlDER
// is non-nil, VCEK revocation is checked against it with no network access.
// It performs no policy validation; callers must validate the returned
// attestation before trusting any report field.
func verifySignature(reportBase64 string, vcekDER, crlDER []byte) (*sevsnp.Attestation, error) {
	reportBytes, err := base64.StdEncoding.DecodeString(reportBase64)
	if err != nil {
		return nil, err
	}

	parsedReport, err := abi.ReportToProto(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	opts := verify.DefaultOptions()
	opts.Getter = &offlineGetter{crlDER: crlDER}
	opts.CheckRevocations = crlDER != nil
	opts.Product = productFromReport(parsedReport)

	attestation := &sevsnp.Attestation{
		Report: parsedReport,
		CertificateChain: &sevsnp.CertificateChain{
			VcekCert: vcekDER,
		},
		Product: opts.Product,
	}

	if err := verify.SnpAttestation(attestation, opts); err != nil {
		return nil, err
	}
	return attestation, nil
}

// Identity returns the machines-map lookup key for a verified SEV-SNP
// report's CHIP_ID field. The field is always 64 bytes; Turin hardware
// delivers its 8-byte hwID zero-padded, which is exactly the endorsed form,
// so no product-specific handling is needed.
func Identity(chipID []byte) (string, error) {
	if len(chipID) != 64 {
		return "", fmt.Errorf("SEV CHIP_ID must be 64 bytes, got %d", len(chipID))
	}
	return hex.EncodeToString(chipID), nil
}
