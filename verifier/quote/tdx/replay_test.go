package tdx

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

func TestPCSReplayGetter(t *testing.T) {
	body := []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":19}}`)
	getter, err := newPCSReplayGetter([]envelope.PCSResponse{{
		URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000&tcbEvaluationDataNumber=19",
		Headers:    map[string][]string{"tcb-info-issuer-chain": {"chain"}},
		BodyBase64: base64.StdEncoding.EncodeToString(body),
	}})
	require.NoError(t, err)

	// The library requests the same resource without the
	// tcbEvaluationDataNumber parameter; the capture must still answer.
	headers, got, err := getter.Get("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000")
	require.NoError(t, err)
	assert.Equal(t, body, got)
	assert.Equal(t, []string{"chain"}, headers["Tcb-Info-Issuer-Chain"])

	_, _, err = getter.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity")
	assert.ErrorContains(t, err, "no captured response")
}

func TestTCBEvaluationRecorder(t *testing.T) {
	inner, err := newPCSReplayGetter([]envelope.PCSResponse{
		{
			URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000",
			BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{"tcbInfo":{"tcbEvaluationDataNumber":20}}`)),
		},
		{
			URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
			BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{"enclaveIdentity":{"tcbEvaluationDataNumber":19}}`)),
		},
	})
	require.NoError(t, err)
	recorder := &tcbEvaluationRecorder{inner: inner}

	_, err = recorder.minimum()
	assert.Error(t, err)

	_, _, err = recorder.Get("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000")
	require.NoError(t, err)
	_, _, err = recorder.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity")
	require.NoError(t, err)

	n, err := recorder.minimum()
	require.NoError(t, err)
	assert.Equal(t, 19, n)
}
