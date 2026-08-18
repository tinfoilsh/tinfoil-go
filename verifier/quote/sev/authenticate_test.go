package sev

import (
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/go-sev-guest/verify"
	sevtestdata "github.com/tinfoilsh/go-sev-guest/verify/testdata"
)

func TestVerifySignatureRejectsNonExactReportSize(t *testing.T) {
	for _, size := range []int{sevabi.ReportSize - 1, sevabi.ReportSize + 1} {
		report := base64.StdEncoding.EncodeToString(make([]byte, size))
		_, err := verifySignature(report, nil, nil, nil, nil)
		assert.ErrorContains(t, err, "must be exactly", "size %d", size)
	}
}

func TestTrustedRootsIncludeTurin(t *testing.T) {
	roots, err := trustedRoots()
	require.NoError(t, err)
	assert.Contains(t, roots, ProductGenoa)
	assert.Contains(t, roots, ProductTurin)
	assert.Equal(t, ProductTurin, roots[ProductTurin][0].ProductLine)
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
	roots, err := trustedRoots()
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
