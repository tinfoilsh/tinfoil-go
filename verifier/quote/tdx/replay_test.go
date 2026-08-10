package tdx

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

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
			getter, err := newPCSReplayGetter([]envelope.PCSResponse{{
				URL:        tc.url,
				BodyBase64: base64.StdEncoding.EncodeToString(tc.body),
			}})
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
