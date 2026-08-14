// Package sev authenticates AMD SEV-SNP reports against the pinned AMD
// roots and assembles complete go-sev-guest validation options from an
// endorsed policy.
package sev

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/go-sev-guest/verify"
	"github.com/tinfoilsh/go-sev-guest/verify/trust"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/strictjson"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

//go:generate sh -xc "curl -fo genoa_cert_chain.pem https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
//go:embed genoa_cert_chain.pem
var askArkGenoaPEM []byte

//go:generate sh -xc "curl -fo turin_cert_chain.pem https://kdsintf.amd.com/vcek/v1/Turin/cert_chain"
//go:embed turin_cert_chain.pem
var askArkTurinPEM []byte

// amdRootPEMOverride, when non-nil, replaces the embedded per-product anchor
// and timeNow is the validity-window clock; production defaults, overridden
// only by the conformance build (see conformance.go).
var (
	amdRootPEMOverride []byte
	timeNow            = time.Now
)

// trustedRoots builds the pinned AMD trust anchors from repo-owned copies
// rather than the library's embedded defaults, so an anchor only changes
// when its file is deliberately regenerated. A fresh instance is built per
// authentication: the library caches the CRL it fetched on this object, and
// document-supplied collateral must never affect other verifications.
func trustedRoots(productLine string) (map[string][]*trust.AMDRootCerts, error) {
	rootPEM := amdRootPEMOverride
	if rootPEM == nil {
		switch productLine {
		case ProductGenoa:
			rootPEM = askArkGenoaPEM
		case ProductTurin:
			rootPEM = askArkTurinPEM
		default:
			return nil, fmt.Errorf("unsupported SEV product line %q", productLine)
		}
	}
	roots := new(trust.AMDRootCerts)
	if err := roots.FromKDSCertBytes(rootPEM); err != nil {
		return nil, fmt.Errorf("parsing embedded AMD %s root certificates: %w", productLine, err)
	}
	roots.ProductLine = productLine
	return map[string][]*trust.AMDRootCerts{productLine: {roots}}, nil
}

// offlineGetter serves the library's fetches from pre-provided material:
// the document-carried CRL. Everything else fails — no network.
type offlineGetter struct {
	crlDER []byte
}

func (g *offlineGetter) Get(targetURL string) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	if strings.HasSuffix(u.Path, "/crl") {
		return g.crlDER, nil
	}
	return nil, fmt.Errorf("offline verification cannot fetch %s", targetURL)
}

// decodeCertChain decodes the document-carried ASK+ARK PEM chain (the AMD
// KDS cert_chain format). The chain is untrusted transport: the library
// verifies it against its pinned AMD root certificates.
func decodeCertChain(chainPEM string) (askDER, arkDER []byte, err error) {
	rest := []byte(chainPEM)
	var blocks [][]byte
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("cert_chain_pem carries a %q block, want CERTIFICATE", block.Type)
		}
		if len(block.Bytes) == 0 {
			return nil, nil, fmt.Errorf("cert_chain_pem carries an empty CERTIFICATE block")
		}
		blocks = append(blocks, block.Bytes)
	}
	if len(blocks) != 2 {
		return nil, nil, fmt.Errorf("cert_chain_pem must carry exactly the ASK and ARK certificates, got %d blocks", len(blocks))
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("cert_chain_pem carries trailing data after the certificates")
	}
	return blocks[0], blocks[1], nil
}

// productFromReport derives the SEV product from the report's CPUID
// family/model/stepping field, present since report version 3 (firmware
// 1.55, the fleet minimum).
func productFromReport(report *sevsnp.Report) (*sevsnp.SevProduct, error) {
	fms := report.GetCpuid1EaxFms()
	if fms == 0 {
		return nil, fmt.Errorf("report carries no CPUID product identity (report version %d, want 3+)", report.GetVersion())
	}
	product := abi.SevProductFromCpuid1Eax(fms)
	switch product.GetName() {
	case sevsnp.SevProduct_SEV_PRODUCT_GENOA, sevsnp.SevProduct_SEV_PRODUCT_TURIN:
		return product, nil
	default:
		return nil, fmt.Errorf("unsupported SEV product in report CPUID 0x%x", fms)
	}
}

// Quote is a signature-verified SEV-SNP report, not yet compared against
// any expected value.
type Quote struct {
	// Identity is the machines-map lookup key (CHIP_ID, lowercase hex).
	Identity string
	// Measurement is the launch measurement register.
	Measurement *measurement.Measurement

	attestation *sevsnp.Attestation
}

// Attestation returns the verified attestation for policy assembly.
func (q *Quote) Attestation() *sevsnp.Attestation { return q.attestation }

// Authenticate verifies the report's signature chain up to the pinned AMD
// root and its VCEK against the document-carried CRL — no network fetches.
// Callers must assemble a policy and validate before trusting the
// platform.
func Authenticate(doc *envelope.Document) (*Quote, error) {
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
	// An empty VCEK would make the library try to fetch one.
	if len(vcekDER) == 0 {
		return nil, fmt.Errorf("amd-vcek collateral entry %q carries an empty VCEK", entry.ID)
	}
	askDER, arkDER, err := decodeCertChain(data.CertChainPEM)
	if err != nil {
		return nil, fmt.Errorf("amd-vcek collateral entry %q: %w", entry.ID, err)
	}
	crlEntry, ok := doc.EndorsementCollateral(envelope.CollateralAMDCRLV1Format, envelope.SubjectCPU)
	if !ok {
		return nil, fmt.Errorf("document carries no amd-crl endorsement collateral for the cpu")
	}
	var crl envelope.AMDCRLCollateral
	if err := strictjson.Unmarshal(crlEntry.Data, &crl); err != nil {
		return nil, fmt.Errorf("parsing amd-crl collateral entry %q: %w", crlEntry.ID, err)
	}
	crlDER, err := base64.StdEncoding.DecodeString(crl.CRLDERBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding crl_der_base64: %w", err)
	}
	if len(crlDER) == 0 {
		return nil, fmt.Errorf("amd-crl collateral entry %q carries an empty CRL", crlEntry.ID)
	}
	// The library verifies the CRL's signature but not its validity window,
	// so a stale pre-revocation CRL would otherwise pass.
	parsedCRL, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, fmt.Errorf("parsing amd-crl collateral: %w", err)
	}
	if now := timeNow(); now.Before(parsedCRL.ThisUpdate) || now.After(parsedCRL.NextUpdate) {
		return nil, fmt.Errorf("amd-crl collateral is outside its validity window (this_update %s, next_update %s)",
			parsedCRL.ThisUpdate.Format(time.RFC3339), parsedCRL.NextUpdate.Format(time.RFC3339))
	}

	att, err := verifySignature(doc.CPUEvidence.ReportBase64, vcekDER, askDER, arkDER, crlDER)
	if err != nil {
		return nil, err
	}
	report := att.GetReport()
	if err := rejectMaskedChipID(report); err != nil {
		return nil, err
	}

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

func rejectMaskedChipID(report *sevsnp.Report) error {
	signer, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return fmt.Errorf("parsing report SIGNER_INFO: %w", err)
	}
	if signer.MaskChipKey {
		return fmt.Errorf("report masks CHIP_ID; masked platform identities are unsupported")
	}
	return nil
}

// verifySignature verifies the report signature under the AMD roots with
// the provided VCEK and ASK/ARK chain, checking VCEK revocation against
// the provided CRL. No policy validation.
func verifySignature(reportBase64 string, vcekDER, askDER, arkDER, crlDER []byte) (*sevsnp.Attestation, error) {
	reportBytes, err := base64.StdEncoding.DecodeString(reportBase64)
	if err != nil {
		return nil, err
	}
	if len(reportBytes) != abi.ReportSize {
		return nil, fmt.Errorf("SEV-SNP report must be exactly %d bytes, got %d", abi.ReportSize, len(reportBytes))
	}

	parsedReport, err := abi.ReportToProto(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	product, err := productFromReport(parsedReport)
	if err != nil {
		return nil, err
	}
	productLine := kds.ProductLine(product)
	roots, err := trustedRoots(productLine)
	if err != nil {
		return nil, err
	}
	// All options explicit. Fetching stays enabled because it is how the
	// library asks for the CRL; the offline getter answers from local
	// material only.
	opts := &verify.Options{
		Getter:           &offlineGetter{crlDER: crlDER},
		CheckRevocations: true,
		TrustedRoots:     roots,
		Product:          product,
		Now:              timeNow(),
	}

	attestation := &sevsnp.Attestation{
		Report: parsedReport,
		CertificateChain: &sevsnp.CertificateChain{
			VcekCert: vcekDER,
			AskCert:  askDER,
			ArkCert:  arkDER,
		},
		Product: opts.Product,
	}

	if err := verify.SnpAttestation(attestation, opts); err != nil {
		return nil, err
	}
	return attestation, nil
}
