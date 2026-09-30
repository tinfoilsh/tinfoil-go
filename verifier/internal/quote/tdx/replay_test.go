package tdx

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func TestPCSReplayGetter(t *testing.T) {
	body := []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":19}}`)
	getter, err := newPCSReplayGetter([]document.PCSResponse{{
		URL:     "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000&tcbEvaluationDataNumber=19",
		Headers: map[string][]string{"tcb-info-issuer-chain": {"chain"}},
		Body:    body,
	}}, time.Now())
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
	inner, err := newPCSReplayGetter([]document.PCSResponse{
		{
			URL:  "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000",
			Body: []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":20}}`),
		},
		{
			URL:  "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
			Body: []byte(`{"enclaveIdentity":{"tcbEvaluationDataNumber":19}}`),
		},
	}, time.Now())
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

func TestPCSReplayGetterValidatesCRL(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		url     string
		body    []byte
		wantErr string
	}{
		"malformed": {
			url:     "https://api.trustedservices.intel.com/tdx/certification/v4/pckcrl?ca=platform",
			body:    []byte("not a CRL"),
			wantErr: "parsing captured CRL",
		},
		"future DER": {
			url:     "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
			body:    testCRL(t, now.Add(time.Hour), now.Add(2*time.Hour)),
			wantErr: "outside its validity window",
		},
		"expired": {
			url:     "https://api.trustedservices.intel.com/tdx/certification/v4/pckcrl?ca=platform",
			body:    testCRL(t, now.Add(-2*time.Hour), now.Add(-time.Hour)),
			wantErr: "outside its validity window",
		},
		"current DER": {
			url:  "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
			body: testCRL(t, now.Add(-time.Hour), now.Add(time.Hour)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			getter, err := newPCSReplayGetter([]document.PCSResponse{{
				URL:  tc.url,
				Body: tc.body,
			}}, now)
			require.NoError(t, err)

			_, body, err := getter.Get(tc.url)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.body, body)
		})
	}
}

func testCRL(t *testing.T, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             thisUpdate.Add(-time.Hour),
		NotAfter:              nextUpdate.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, crypto.Signer(privateKey))
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}, issuer, privateKey)
	require.NoError(t, err)
	return crlDER
}

func TestPCSReplayGetterReturnsPrivateBuffers(t *testing.T) {
	body := []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":19}}`)
	url := "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000"
	getter, err := newPCSReplayGetter([]document.PCSResponse{{URL: url, Body: body}}, time.Now())
	require.NoError(t, err)

	_, first, err := getter.Get(url)
	require.NoError(t, err)
	first[0] = '!'
	_, second, err := getter.Get(url)
	require.NoError(t, err)
	assert.Equal(t, body, second, "a consumer changing one response must not affect the next replay")
	assert.Equal(t, byte('{'), body[0], "the caller's endorsements stay unchanged")
}
