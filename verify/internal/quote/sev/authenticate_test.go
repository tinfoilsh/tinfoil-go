package sev

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	sevtesting "github.com/tinfoilsh/go-sev-guest/testing"
	"github.com/tinfoilsh/go-sev-guest/verify"

	sevtestdata "github.com/tinfoilsh/tinfoil-go/verify/internal/testdata"
)

func TestVerifiedCertificateExpiry(t *testing.T) {
	now := time.Date(2026, time.November, 6, 0, 0, 0, 0, time.UTC)
	for first, name := range []string{"VCEK", "pinned ASK", "pinned ARK"} {
		t.Run(name, func(t *testing.T) {
			raw, err := sevtestdata.Box2TurinReport()
			require.NoError(t, err)
			report, err := sevabi.ReportToProto(raw)
			require.NoError(t, err)
			builder := &sevtesting.AmdSignerBuilder{
				ProductName:     kds.ProductName(sevabi.SevProductFromCpuid1Eax(report.Cpuid1EaxFms)),
				TCB:             kds.TCBVersion(report.ReportedTcb),
				ArkCreationTime: now, AskCreationTime: now, AsvkCreationTime: now, VcekCreationTime: now, VlekCreationTime: now,
				ArkCustom: sevtesting.CertOverride{KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
			}
			copy(builder.HWID[:], report.ChipId)
			signer, err := builder.TestOnlyCertChain()
			require.NoError(t, err)
			certs := []*x509.Certificate{signer.Vcek, signer.Ask, signer.Ark}
			parents := []*x509.Certificate{signer.Ask, signer.Ark, signer.Ark}
			keys := []crypto.Signer{signer.Keys.Ask, signer.Keys.Ark, signer.Keys.Ark}
			der := make([][]byte, len(certs))
			for i, cert := range certs {
				cert.NotAfter = now.Add(24 * time.Hour)
				if i == first {
					cert.NotAfter = now.Add(time.Hour)
				}
				cert.ExtraExtensions = cert.Extensions
				der[i], err = x509.CreateCertificate(rand.Reader, cert, parents[i], cert.PublicKey, keys[i])
				require.NoError(t, err)
			}
			chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[1]})
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[2]})...)
			crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour),
			}, signer.Ark, signer.Keys.Ark)
			require.NoError(t, err)
			r, s, err := signer.Sign(sevabi.SignedComponent(raw))
			require.NoError(t, err)
			require.NoError(t, sevabi.SetSignature(r, s, raw))
			_, expiresAt, err := verifySignature(raw, der[0], signer.Ask.Raw, signer.Ark.Raw, crl, now, chain)
			require.NoError(t, err)
			require.Equal(t, now.Add(time.Hour), expiresAt)
			_, _, err = verifySignature(raw, der[0], signer.Ask.Raw, signer.Ark.Raw, crl, expiresAt.Add(time.Second), chain)
			require.ErrorContains(t, err, "expired")
		})
	}
}

func TestVerifySignatureRejectsNonExactReportSize(t *testing.T) {
	for _, size := range []int{sevabi.ReportSize - 1, sevabi.ReportSize + 1} {
		_, _, err := verifySignature(make([]byte, size), nil, nil, nil, nil, time.Now(), nil)
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
