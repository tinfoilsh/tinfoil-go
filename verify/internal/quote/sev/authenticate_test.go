package sev

import (
	"bytes"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/go-sev-guest/verify"

	sevtestdata "github.com/tinfoilsh/tinfoil-go/verify/internal/testdata"
)

func TestVerifySignatureRejectsNonExactReportSize(t *testing.T) {
	for _, size := range []int{sevabi.ReportSize - 1, sevabi.ReportSize + 1} {
		_, err := verifySignature(make([]byte, size), nil, nil, nil, nil, time.Now(), nil)
		assert.ErrorContains(t, err, "must be exactly", "size %d", size)
	}
}

func TestAuthenticateRequiresVerificationTime(t *testing.T) {
	_, err := Authenticate(Evidence{}, time.Time{}, nil)
	assert.ErrorContains(t, err, "verification time is required", "the library would substitute its own clock")
}

func TestTrustedRootsSelectProduct(t *testing.T) {
	for _, productLine := range []string{ProductGenoa, ProductTurin} {
		t.Run(productLine, func(t *testing.T) {
			roots, err := trustedRoots(productLine, nil)
			require.NoError(t, err)
			require.Len(t, roots, 1)
			require.Len(t, roots[productLine], 1)
			assert.Equal(t, productLine, roots[productLine][0].ProductLine)
		})
	}

	_, err := trustedRoots("Milan", nil)
	assert.ErrorContains(t, err, "unsupported SEV product line")
}

func TestProductFromReportRejectsUnknownProduct(t *testing.T) {
	report := &sevsnp.Report{
		Version:      sevabi.ReportVersion5,
		Cpuid1EaxFms: sevabi.FmsToCpuid1Eax(0xff, 0xff, 0),
	}
	_, err := productFromReport(report)
	assert.ErrorContains(t, err, "unsupported SEV product")
}

func TestVerifyBox2TurinSignatureWithPinnedRoots(t *testing.T) {
	reportRaw, err := sevtestdata.Box2TurinReport()
	require.NoError(t, err)
	report, err := sevabi.ReportToProto(reportRaw)
	require.NoError(t, err)
	vcek, err := sevtestdata.Box2TurinVcek()
	require.NoError(t, err)
	ask, ark, err := decodeCertChain(string(askArkTurinPEM))
	require.NoError(t, err)
	product, err := productFromReport(report)
	require.NoError(t, err)
	roots, err := trustedRoots(ProductTurin, nil)
	require.NoError(t, err)
	attestation := &sevsnp.Attestation{
		Report: report,
		CertificateChain: &sevsnp.CertificateChain{
			VcekCert: vcek,
			AskCert:  ask,
			ArkCert:  ark,
		},
		Product: product,
	}
	opts := &verify.Options{
		DisableCertFetching: true,
		TrustedRoots:        roots,
		Product:             product,
		Now:                 time.Date(2026, time.August, 18, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, verify.SnpAttestation(attestation, opts))
}

func TestDecodeCertChainRejectsEmptyCertificate(t *testing.T) {
	emptyCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE"})
	chain := string(append(emptyCertificate, emptyCertificate...))

	_, _, err := decodeCertChain(chain)
	assert.ErrorContains(t, err, "empty CERTIFICATE block")
}

// go-sev-guest verifies the signature over a re-encoding of the report that
// drops the high four bits of the CPUID stepping byte, so those bits must be
// refused rather than left unsigned.
func TestVerifySignatureRejectsNonCanonicalReport(t *testing.T) {
	reportRaw, err := sevtestdata.Box2TurinReport()
	require.NoError(t, err)
	parsed, err := sevabi.ReportToProto(reportRaw)
	require.NoError(t, err)
	reencoded, err := sevabi.ReportToAbiBytes(parsed)
	require.NoError(t, err)
	require.Equal(t, reportRaw, reencoded, "a genuine report is canonical")

	const steppingOffset = 0x18A
	for _, bit := range []byte{0x10, 0x20, 0x40, 0x80} {
		report := bytes.Clone(reportRaw)
		report[steppingOffset] |= bit
		_, err := verifySignature(report, nil, nil, nil, nil, time.Now(), nil)
		assert.ErrorContains(t, err, "not in canonical form", "stepping bit %#x", bit)
	}
}
