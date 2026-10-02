package document

import (
	"bytes"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/errs"
)

func testCryptoMaterial() []CryptoMaterialItem {
	return []CryptoMaterialItem{
		{ID: CryptoMaterialIDTLS, Format: KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))},
		{ID: CryptoMaterialIDHPKE, Format: KeyX25519HPKEV1Format, Data: hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 32))},
	}
}

// fakeQuote returns a QuoteGenerator that records the REPORT_DATA it was
// asked to sign.
func fakeQuote(format string, report []byte, signed *[64]byte) QuoteGenerator {
	return func(reportData [64]byte) (string, []byte, error) {
		if signed != nil {
			*signed = reportData
		}
		return format, report, nil
	}
}

func TestBuildRoundTrip(t *testing.T) {
	nonce := testNonce()
	in := BuildInput{
		Nonce:          nonce,
		CryptoMaterial: testCryptoMaterial(),
		DeviceEvidence: []DeviceEvidenceItem{{ID: "gpu0", Kind: "gpu", Vendor: "nvidia", Format: NvidiaGPUEvidenceV1Format, Evidence: jsontext.Value(`{"report":"x"}`)}},
		Collateral:     []collateral.Entry{{ID: "vcek", Role: collateral.RoleEndorsement, Format: collateral.AMDVCEKV1Format, Subjects: []string{collateral.SubjectCPU}, Data: jsontext.Value(`{"vcek_der_base64":"","cert_chain_pem":""}`)}},
	}
	var signed [64]byte
	report := bytes.Repeat([]byte{0x01}, 1184)
	docBytes, err := Build(in, fakeQuote(SEVSNPReportV1Format, report, &signed))
	require.NoError(t, err)

	doc, err := Parse(docBytes, nonce)
	require.NoError(t, err)
	reportData, ok := doc.ExpectedReportData()
	require.True(t, ok)
	assert.Equal(t, signed, reportData, "the quote signs the REPORT_DATA a verifier recomputes")
	assert.Equal(t, in.CryptoMaterial, doc.CryptoMaterialItems())
	assert.Equal(t, in.DeviceEvidence, doc.DeviceEvidenceItems())
	assert.Equal(t, CPUEvidence{Format: SEVSNPReportV1Format, Report: report}, doc.CPUEvidence())
	assert.Equal(t, &collateral.AMDVCEK{VCEKDER: []byte{}, CertChainPEM: ""}, doc.CPUEndorsements().AMDVCEK, "the vcek entry is decoded and serves the CPU")
}

func TestBuildAcceptsEmptySections(t *testing.T) {
	nonce := testNonce()
	docBytes, err := Build(BuildInput{Nonce: nonce}, fakeQuote(TDXQuoteV1Format, []byte("quote"), nil))
	require.NoError(t, err)
	doc, err := Parse(docBytes, nonce)
	require.NoError(t, err)
	assert.Empty(t, doc.CryptoMaterialItems())
	assert.Empty(t, doc.DeviceEvidenceItems())
}

func TestBuildRejectsInvalidEndorsedInput(t *testing.T) {
	nonce := testNonce()
	shortKey := testCryptoMaterial()
	shortKey[0].Data = hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 8))
	for _, tt := range []struct {
		name    string
		in      BuildInput
		wantErr string
	}{
		{name: "short nonce", in: BuildInput{Nonce: nonce[:NonceSize-1]}, wantErr: "nonce must be 32 bytes"},
		{name: "duplicate key id", in: BuildInput{Nonce: nonce, CryptoMaterial: append(testCryptoMaterial(), testCryptoMaterial()[0])}, wantErr: `duplicate crypto_material item id "tls"`},
		{name: "short key", in: BuildInput{Nonce: nonce, CryptoMaterial: shortKey}, wantErr: "must be 32 bytes"},
		{name: "device without id", in: BuildInput{Nonce: nonce, DeviceEvidence: []DeviceEvidenceItem{{Evidence: jsontext.Value(`{}`)}}}, wantErr: "device_evidence item has no id"},
		{name: "duplicate device id", in: BuildInput{Nonce: nonce, DeviceEvidence: []DeviceEvidenceItem{{ID: "gpu0", Evidence: jsontext.Value(`{}`)}, {ID: "gpu0", Evidence: jsontext.Value(`{}`)}}}, wantErr: `duplicate device_evidence item id "gpu0"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			_, err := Build(tt.in, func([64]byte) (string, []byte, error) {
				called = true
				return SEVSNPReportV1Format, []byte("quote"), nil
			})
			var config *errs.ConfigurationError
			require.ErrorAs(t, err, &config)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.False(t, called, "no quote is generated for input that cannot become a document")
		})
	}
}

func TestBuildRejectsInvalidCollateralBeforeQuoting(t *testing.T) {
	entry := collateral.Entry{ID: "crl", Role: collateral.RoleEndorsement, Format: collateral.AMDCRLV1Format, Subjects: []string{collateral.SubjectCPU}, Data: jsontext.Value(`{}`)}
	unknownRole := entry
	unknownRole.Role = "unknown"
	malformed := collateral.Entry{ID: "future", Role: collateral.RoleEndorsement, Format: "https://tinfoil.sh/collateral/unknown/v9", Data: jsontext.Value(`{bad`)}
	for _, tt := range []struct {
		name       string
		collateral []collateral.Entry
		wantErr    string
	}{
		{name: "unknown role", collateral: []collateral.Entry{unknownRole}, wantErr: `unknown role "unknown"`},
		{name: "duplicate id", collateral: []collateral.Entry{entry, entry}, wantErr: `duplicate collateral entry id "crl"`},
		{name: "malformed data", collateral: []collateral.Entry{malformed}, wantErr: `collateral entry "future" data is not a valid JSON object`},
		{name: "invalid utf-8 id", collateral: []collateral.Entry{{ID: "\xff", Role: collateral.RoleEndorsement, Format: "https://tinfoil.sh/collateral/unknown/v9", Data: jsontext.Value(`{}`)}}, wantErr: "serializing collateral"},
		{name: "missing data", collateral: []collateral.Entry{{ID: "future", Role: collateral.RoleEndorsement, Format: "https://tinfoil.sh/collateral/unknown/v9"}}, wantErr: `collateral entry "future" data is not a valid JSON object`},
		{name: "non-canonical vcek", collateral: []collateral.Entry{{ID: "vcek", Role: collateral.RoleEndorsement, Format: collateral.AMDVCEKV1Format, Subjects: []string{collateral.SubjectCPU}, Data: jsontext.Value(`{"vcek_der_base64":"AAAA\n","cert_chain_pem":""}`)}}, wantErr: "vcek_der_base64 is not canonical base64"},
		{name: "unknown member in known format", collateral: []collateral.Entry{{ID: "crl", Role: collateral.RoleEndorsement, Format: collateral.AMDCRLV1Format, Subjects: []string{collateral.SubjectCPU}, Data: jsontext.Value(`{"crl_der_base64":"","unknown":1}`)}}, wantErr: `parsing amd-crl collateral entry "crl"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			_, err := Build(BuildInput{Nonce: testNonce(), Collateral: tt.collateral}, func([64]byte) (string, []byte, error) {
				called = true
				return SEVSNPReportV1Format, []byte("quote"), nil
			})
			var config *errs.ConfigurationError
			require.ErrorAs(t, err, &config)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.False(t, called, "invalid collateral must not cost a hardware quote")
		})
	}
}

func TestBuildRejectsBadQuoteGeneratorOutput(t *testing.T) {
	for _, tt := range []struct {
		name    string
		format  string
		report  []byte
		wantErr string
	}{
		{name: "empty format", format: "", report: []byte("quote"), wantErr: `unsupported evidence format ""`},
		{name: "unknown format", format: "https://tinfoil.sh/format/unknown/v1", report: []byte("quote"), wantErr: "unsupported evidence format"},
		{name: "empty report", format: SEVSNPReportV1Format, report: nil, wantErr: "empty report"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Build(BuildInput{Nonce: testNonce()}, fakeQuote(tt.format, tt.report, nil))
			assert.ErrorContains(t, err, tt.wantErr)
			var config *errs.ConfigurationError
			assert.False(t, errors.As(err, &config), "bad generator output is not the caller's configuration error")
		})
	}
}

func TestBuildPassesThroughQuoteErrors(t *testing.T) {
	hardware := errors.New("quote generation failed")
	_, err := Build(BuildInput{Nonce: testNonce()}, func([64]byte) (string, []byte, error) {
		return "", nil, hardware
	})
	require.ErrorIs(t, err, hardware)
	var config *errs.ConfigurationError
	assert.False(t, errors.As(err, &config), "a hardware failure is not the producer's configuration error")

	_, err = Build(BuildInput{Nonce: testNonce()}, nil)
	require.ErrorAs(t, err, &config)
}

func TestBuildCopiesTheNonce(t *testing.T) {
	nonce := testNonce()
	want := bytes.Clone(nonce)
	docBytes, err := Build(BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) {
		// A caller reusing its buffer mid-build must not change the document.
		nonce[0] ^= 0xff
		return SEVSNPReportV1Format, []byte("quote"), nil
	})
	require.NoError(t, err)
	_, err = Parse(docBytes, want)
	require.NoError(t, err)
}
