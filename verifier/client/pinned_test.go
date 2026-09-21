package client

import (
	"encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

const workloadRegisterBytes = 48

func TestWorkloadPinConfiguration(t *testing.T) {
	register := strings.Repeat("ab", workloadRegisterBytes)
	gpus := 1
	opts := VerificationOptions{
		PinnedCode:      &measurement.CodeMeasurement{TDXMeasurement: &measurement.TDXMeasurement{RTMR1: strings.ToUpper(register), RTMR2: register}},
		PinnedShape:     &policy.Shape{CPUs: 4, MemoryMB: 8192, Disks: 1, GPUs: &gpus},
		FreshnessMaxAge: time.Hour,
	}
	c, err := NewSecureClient("enclave.example:8443", "", &opts)
	require.NoError(t, err)
	opts.PinnedCode.TDXMeasurement.RTMR1 = "changed"
	opts.PinnedShape.CPUs = 8
	gpus = 2
	opts.FreshnessMaxAge = time.Minute
	require.Equal(t, register, c.options.PinnedCode.TDXMeasurement.RTMR1)
	require.Equal(t, 4, c.options.PinnedShape.CPUs)
	require.Equal(t, 1, *c.options.PinnedShape.GPUs)
	require.Equal(t, time.Hour, c.options.FreshnessMaxAge)
	require.Equal(t, "enclave.example:8443", c.Enclave())
	require.Empty(t, c.Repo())
	require.Nil(t, c.Verification())

	combined := &measurement.CodeMeasurement{SNPMeasurement: register, TDXMeasurement: &measurement.TDXMeasurement{RTMR1: register, RTMR2: register}}
	_, err = NewSecureClient("enclave.example", "", &VerificationOptions{PinnedCode: combined})
	require.NoError(t, err, "a multiplatform pin can target SNP without a shape")
}

func TestWorkloadPinRejectsInvalidConfiguration(t *testing.T) {
	register := strings.Repeat("ab", workloadRegisterBytes)
	snp := &measurement.CodeMeasurement{SNPMeasurement: register}
	tdx := &measurement.CodeMeasurement{TDXMeasurement: &measurement.TDXMeasurement{RTMR1: register, RTMR2: register}}
	negativeGPU := -1
	for name, opts := range map[string]VerificationOptions{
		"empty pin":             {PinnedCode: &measurement.CodeMeasurement{}},
		"malformed pin":         {PinnedCode: &measurement.CodeMeasurement{SNPMeasurement: "abc"}},
		"TDX needs shape":       {PinnedCode: tdx},
		"shape needs pin":       {PinnedShape: &policy.Shape{}},
		"negative CPUs":         {PinnedCode: tdx, PinnedShape: &policy.Shape{CPUs: -1}},
		"negative memory":       {PinnedCode: tdx, PinnedShape: &policy.Shape{MemoryMB: -1}},
		"negative disks":        {PinnedCode: tdx, PinnedShape: &policy.Shape{Disks: -1}},
		"negative GPUs":         {PinnedCode: tdx, PinnedShape: &policy.Shape{GPUs: &negativeGPU}},
		"negative age":          {PinnedCode: snp, FreshnessMaxAge: -time.Second},
		"register pin conflict": {PinnedCode: snp, PinnedRegisters: &measurement.Measurement{}},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewSecureClient("enclave.example", "", &opts)
			require.Error(t, err)
			require.Nil(t, c)
			_, err = VerifyDocumentV3(nil, nil, "", &opts)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "envelope:", "configuration must fail before document processing")
		})
	}
	opts := &VerificationOptions{PinnedCode: snp}
	_, err := NewSecureClient("", "", opts)
	require.ErrorContains(t, err, "explicit enclave")
	_, err = NewDefaultClient(opts)
	require.ErrorContains(t, err, "explicit enclave")
	_, err = NewSecureClient("enclave.example", "org/repo", opts)
	require.ErrorContains(t, err, "source repository")
	_, err = VerifyDocumentV3(nil, nil, "org/repo", opts)
	require.ErrorContains(t, err, "source repository")
}

func TestWorkloadPinRequiresMatchingPlatform(t *testing.T) {
	snp, rtmr1, rtmr2 := strings.Repeat("aa", workloadRegisterBytes), strings.Repeat("bb", workloadRegisterBytes), strings.Repeat("cc", workloadRegisterBytes)
	combined := &measurement.CodeMeasurement{SNPMeasurement: snp, TDXMeasurement: &measurement.TDXMeasurement{RTMR1: rtmr1, RTMR2: rtmr2}}
	for _, format := range []string{envelope.SEVSNPReportV1Format, envelope.TDXQuoteV1Format} {
		got, err := pinnedCodeMeasurement(combined, format)
		require.NoError(t, err)
		require.Equal(t, &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{snp, rtmr1, rtmr2}}, got)
	}
	got, err := pinnedCodeMeasurement(&measurement.CodeMeasurement{TDXMeasurement: combined.TDXMeasurement}, envelope.TDXQuoteV1Format)
	require.NoError(t, err)
	require.Equal(t, []string{"", rtmr1, rtmr2}, got.Registers)
	_, err = pinnedCodeMeasurement(&measurement.CodeMeasurement{SNPMeasurement: snp}, envelope.TDXQuoteV1Format)
	require.ErrorContains(t, err, "requires tdx_measurement")
	_, err = pinnedCodeMeasurement(&measurement.CodeMeasurement{TDXMeasurement: combined.TDXMeasurement}, envelope.SEVSNPReportV1Format)
	require.ErrorContains(t, err, "requires snp_measurement")
}

func TestVerifyWorkloadPin(t *testing.T) {
	host, repo := os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO")
	if host == "" || repo == "" {
		t.Skip("TINFOIL_ENCLAVE or TINFOIL_REPO not set")
	}
	nonce, err := envelope.RandomNonce()
	require.NoError(t, err)
	raw, err := envelope.Fetch(host, nonce)
	require.NoError(t, err)
	release, err := VerifyDocumentV3(raw, nonce, repo, nil)
	require.NoError(t, err)
	if release.EnclaveMeasurement.Type != measurement.SevGuestV2 {
		t.Skip("this live test requires SNP; TDX needs a known VM shape")
	}
	register := release.EnclaveMeasurement.Registers[0]
	opts := &VerificationOptions{PinnedCode: &measurement.CodeMeasurement{SNPMeasurement: strings.ToUpper(register)}}
	doc, err := envelope.Parse(raw)
	require.NoError(t, err)
	withoutCode := *doc
	withoutCode.Collateral = nil
	for _, entry := range doc.Collateral {
		if entry.Format != envelope.CollateralSigstoreCodeV1Format && entry.ID != envelope.FreshnessCollateralIDCode {
			withoutCode.Collateral = append(withoutCode.Collateral, entry)
		}
	}
	stripped, err := json.Marshal(&withoutCode)
	require.NoError(t, err)
	_, err = VerifyDocumentV3(stripped, nonce, repo, nil)
	require.Error(t, err, "release mode must still require code provenance")
	verified, err := VerifyDocumentV3(stripped, nonce, "", opts)
	require.NoError(t, err)
	require.Equal(t, PinnedNoRepo, verified.ConfigRepo)
	require.Equal(t, PinnedNoDigest, verified.CodeDigest)
	require.Empty(t, verified.CodeTag)
	require.Equal(t, register, verified.CodeMeasurement.Registers[0])
	require.Equal(t, release.EnclaveMeasurement, verified.EnclaveMeasurement)
	require.Equal(t, release.CryptoMaterial, verified.CryptoMaterial)
	require.True(t, verified.FreshnessExpiresAt.After(time.Now()))
	ignoredCode := *doc
	ignoredCode.Collateral = append([]envelope.CollateralEntry(nil), doc.Collateral...)
	for i := range ignoredCode.Collateral {
		entry := &ignoredCode.Collateral[i]
		if entry.Format == envelope.CollateralSigstoreCodeV1Format || entry.ID == envelope.FreshnessCollateralIDCode {
			entry.Data = []byte(`{}`)
		}
	}
	invalidCode, err := json.Marshal(&ignoredCode)
	require.NoError(t, err)
	_, err = VerifyDocumentV3(invalidCode, nonce, "", opts)
	require.NoError(t, err, "supplied code collateral must not affect a workload pin")

	longer := *opts
	longer.FreshnessMaxAge = provenance.MaxFreshnessAge + time.Hour
	verifiedLonger, err := VerifyDocumentV3(stripped, nonce, "", &longer)
	require.NoError(t, err)
	require.Equal(t, verified.FreshnessExpiresAt.Add(time.Hour), verifiedLonger.FreshnessExpiresAt)
	stale := *opts
	stale.FreshnessMaxAge = time.Nanosecond
	_, err = VerifyDocumentV3(stripped, nonce, "", &stale)
	require.ErrorContains(t, err, "freshness witness is stale")

	for _, format := range []string{envelope.CollateralSigstorePlatformV1Format, envelope.CollateralSigstoreFreshnessV1Format} {
		missing := withoutCode
		missing.Collateral = nil
		for _, entry := range withoutCode.Collateral {
			if entry.Format != format {
				missing.Collateral = append(missing.Collateral, entry)
			}
		}
		bad, err := json.Marshal(&missing)
		require.NoError(t, err)
		_, err = VerifyDocumentV3(bad, nonce, "", opts)
		require.Error(t, err, "platform provenance and freshness remain mandatory")
	}
	wrongNonce := append([]byte(nil), nonce...)
	wrongNonce[0] ^= 1
	_, err = VerifyDocumentV3(stripped, wrongNonce, "", opts)
	require.Error(t, err)
	wrongPin := &VerificationOptions{PinnedCode: &measurement.CodeMeasurement{SNPMeasurement: "0" + register[1:]}}
	if wrongPin.PinnedCode.SNPMeasurement == register {
		wrongPin.PinnedCode.SNPMeasurement = "1" + register[1:]
	}
	for _, evidence := range [][]byte{raw, stripped} {
		_, err = VerifyDocumentV3(evidence, nonce, "", wrongPin)
		require.ErrorContains(t, err, "cpu evidence:", "valid release provenance must not override a mismatched pin")
	}

	c, err := NewSecureClient(host, "", opts)
	require.NoError(t, err)
	opts.PinnedCode.SNPMeasurement = wrongPin.PinnedCode.SNPMeasurement
	for range 2 {
		result, err := c.Verify()
		require.NoError(t, err, "refresh must retain the original workload pin")
		require.Equal(t, PinnedNoDigest, result.CodeDigest)
		require.Equal(t, register, result.CodeMeasurement.Registers[0])
		result.CodeMeasurement.Registers[0] = "changed"
		require.Equal(t, register, c.Verification().CodeMeasurement.Registers[0])
	}
}
