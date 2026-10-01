package tdx

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/policy"
)

func TestIGVMEnforcesConfigPaddingAndEveryRuntimeRegister(t *testing.T) {
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	quote, ok := parsed.(*tdxpb.QuoteV4)
	require.True(t, ok)
	q := &Quote{quote: quote, tcbEvaluationDataNumber: 5}
	body := q.quote.TdQuoteBody
	configHash := sha256.Sum256([]byte("approved YAML bytes"))
	body.MrConfigId = make([]byte, igvm.MeasurementSize)
	copy(body.MrConfigId, configHash[:])
	for i := range body.Rtmrs {
		body.Rtmrs[i] = make([]byte, igvm.MeasurementSize)
	}
	zero := strings.Repeat("0", igvm.MeasurementSize*2)
	runtime := &igvm.TDXLaunch{MRTD: hex.EncodeToString(body.MrTd), RTMR0: zero, RTMR1: zero, RTMR2: zero, RTMR3: zero}
	minimum := 5
	p := &policy.TDXPolicy{
		QEVendorID: hex.EncodeToString(q.quote.Header.QeVendorId), MinimumTEETCBSVN: hex.EncodeToString(body.TeeTcbSvn),
		MRSeam: hex.EncodeToString(body.MrSeam), TDAttributes: hex.EncodeToString(body.TdAttributes), XFAM: hex.EncodeToString(body.Xfam),
		MinimumTCBEvaluationDataNumber: &minimum, ConfigBinding: policy.ConfigBindingSHA256,
	}
	var reportData [64]byte
	copy(reportData[:], body.ReportData)
	e, err := AssembleIGVM(p, runtime, configHash, reportData)
	require.NoError(t, err)
	require.NoError(t, e.Validate(q))
	_, _, err = Assemble(&policy.Artifact{}, p, &policy.Shape{}, q, runtime.Registers(), reportData)
	require.ErrorContains(t, err, "requires IGVM")
	for name, mutate := range map[string]func(*tdxpb.TDQuoteBody){
		"config hash":    func(b *tdxpb.TDQuoteBody) { b.MrConfigId[0] ^= 1 },
		"config padding": func(b *tdxpb.TDQuoteBody) { b.MrConfigId[sha256.Size] = 1 },
		"MRTD":           func(b *tdxpb.TDQuoteBody) { b.MrTd[0] ^= 1 },
		"RTMR0":          func(b *tdxpb.TDQuoteBody) { b.Rtmrs[0][0] ^= 1 },
		"RTMR1":          func(b *tdxpb.TDQuoteBody) { b.Rtmrs[1][0] ^= 1 },
		"RTMR2":          func(b *tdxpb.TDQuoteBody) { b.Rtmrs[2][0] ^= 1 },
		"RTMR3":          func(b *tdxpb.TDQuoteBody) { b.Rtmrs[3][0] ^= 1 },
		"MRSEAM":         func(b *tdxpb.TDQuoteBody) { b.MrSeam[0] ^= 1 },
		"attributes":     func(b *tdxpb.TDQuoteBody) { b.TdAttributes[0] ^= 1 },
		"REPORT_DATA":    func(b *tdxpb.TDQuoteBody) { b.ReportData[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *q
			bad.quote = proto.Clone(q.quote).(*tdxpb.QuoteV4)
			mutate(bad.quote.TdQuoteBody)
			require.Error(t, e.Validate(&bad))
		})
	}
	bad := *q
	bad.tcbEvaluationDataNumber = minimum - 1
	require.ErrorContains(t, e.Validate(&bad), "below the policy minimum")
	p.ConfigBinding = ""
	_, err = AssembleIGVM(p, runtime, configHash, reportData)
	require.ErrorContains(t, err, "config-binding")
}
