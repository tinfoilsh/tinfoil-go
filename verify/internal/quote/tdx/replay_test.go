package tdx

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/validity"
)

func TestRecordedCollateralExpiry(t *testing.T) {
	const (
		tcbURL    = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000"
		qeURL     = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
		pckURL    = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform"
		rootURL   = "https://certificates.trustedservices.intel.com/root.der"
		unusedURL = "https://example.test/unused.der"
	)
	now := time.Date(2026, time.November, 6, 0, 0, 0, 0, time.UTC)
	early, later := now.Add(time.Hour), now.Add(24*time.Hour)
	for first, name := range []string{"TCB Info", "QE Identity", "PCK CRL", "root CRL", "TCB issuer", "QE issuer", "PCK CRL issuer"} {
		t.Run(name, func(t *testing.T) {
			deadlines := []time.Time{later, later, later, later, later, later, later}
			deadlines[first] = early
			responses := []collateral.PCSResponse{
				{URL: tcbURL, Headers: map[string][]string{tcbInfoIssuerChainHeader: {url.QueryEscape(string(expiringCertificate(t, now, deadlines[4])))}}, Body: fmt.Appendf(nil, `{"tcbInfo":{"tcbEvaluationDataNumber":20,"nextUpdate":%q},"signature":""}`, deadlines[0].Format(time.RFC3339))},
				{URL: qeURL, Headers: map[string][]string{qeIdentityIssuerChainHeader: {url.QueryEscape(string(expiringCertificate(t, now, deadlines[5])))}}, Body: fmt.Appendf(nil, `{"enclaveIdentity":{"tcbEvaluationDataNumber":20,"nextUpdate":%q},"signature":""}`, deadlines[1].Format(time.RFC3339))},
				{URL: pckURL, Headers: map[string][]string{pckCRLIssuerChainHeader: {url.QueryEscape(string(expiringCertificate(t, now, deadlines[6])))}}, Body: testCRL(t, now, deadlines[2])},
				{URL: rootURL, Headers: map[string][]string{"": {"unused"}}, Body: testCRL(t, now, deadlines[3])},
				{URL: unusedURL, Body: testCRL(t, now, now.Add(time.Minute))},
			}
			getter, err := newPCSReplayGetter(responses, now)
			require.NoError(t, err)
			recorder := &tcbEvaluationRecorder{inner: getter}
			for _, target := range []string{tcbURL, qeURL, pckURL, rootURL} {
				_, _, err := recorder.Get(target)
				require.NoError(t, err)
			}
			require.Equal(t, early, validity.Earliest(getter.expiresAt, recorder.expiresAt))
		})
	}
}

func TestCertificateChainExpiry(t *testing.T) {
	now := time.Date(2026, time.November, 6, 0, 0, 0, 0, time.UTC)
	early, later := now.Add(time.Hour), now.Add(24*time.Hour)
	for _, deadlines := range [][3]time.Time{{early, later, later}, {later, early, later}, {later, later, early}} {
		var chain []byte
		for _, deadline := range deadlines {
			chain = append(chain, expiringCertificate(t, now, deadline)...)
		}
		for _, suffix := range [][]byte{nil, {0}} {
			expiresAt, err := certificateChainExpiry(append(slices.Clone(chain), suffix...))
			require.NoError(t, err)
			require.Equal(t, early, expiresAt)
		}
	}
}

func expiringCertificate(t *testing.T, now, expiresAt time.Time) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now, NotAfter: expiresAt}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPCSReplayGetter(t *testing.T) {
	body := []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":19},"signature":""}`)
	getter, err := newPCSReplayGetter([]collateral.PCSResponse{{
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
	inner, err := newPCSReplayGetter([]collateral.PCSResponse{
		{
			URL:  "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000",
			Body: []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":20},"signature":""}`),
		},
		{
			URL:  "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
			Body: []byte(`{"enclaveIdentity":{"tcbEvaluationDataNumber":19},"signature":""}`),
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

// go-tdx-guest checks only nextUpdate, so the recorder rejects TCB Info and QE
// Identity issued after the verification time.
func TestTCBEvaluationRecorderRejectsCollateralIssuedLater(t *testing.T) {
	const tcbURL = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000"
	const qeURL = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	now := time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC)
	later := now.Add(time.Second)
	body := func(object string, issued time.Time) []byte {
		if issued.IsZero() {
			return fmt.Appendf(nil, `{%q:{"tcbEvaluationDataNumber":20},"signature":""}`, object)
		}
		return fmt.Appendf(nil, `{%q:{"tcbEvaluationDataNumber":20,"issueDate":%q},"signature":""}`, object, issued.Format(time.RFC3339))
	}
	for _, tt := range []struct {
		name                string
		tcbInfo, qeIdentity time.Time
		wantError           string
	}{
		{"issued at the verification time", now, now, ""},
		{"TCB Info issued later", later, now, "TCB Info is not yet valid"},
		{"QE Identity issued later", now, later, "QE Identity is not yet valid"},
		{"no issue date", time.Time{}, now, "issueDate was not observed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inner, err := newPCSReplayGetter([]collateral.PCSResponse{
				{URL: tcbURL, Body: body("tcbInfo", tt.tcbInfo)},
				{URL: qeURL, Body: body("enclaveIdentity", tt.qeIdentity)},
			}, now)
			require.NoError(t, err)
			recorder := &tcbEvaluationRecorder{inner: inner}
			for _, u := range []string{tcbURL, qeURL} {
				_, _, err = recorder.Get(u)
				require.NoError(t, err)
			}
			err = recorder.checkIssueDates(now)
			if tt.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantError)
		})
	}
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
			getter, err := newPCSReplayGetter([]collateral.PCSResponse{{
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
	body := []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":19},"signature":""}`)
	url := "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000"
	getter, err := newPCSReplayGetter([]collateral.PCSResponse{{URL: url, Body: body}}, time.Now())
	require.NoError(t, err)

	_, first, err := getter.Get(url)
	require.NoError(t, err)
	first[0] = '!'
	_, second, err := getter.Get(url)
	require.NoError(t, err)
	assert.Equal(t, body, second, "a consumer changing one response must not affect the next replay")
	assert.Equal(t, byte('{'), body[0], "the caller's endorsements stay unchanged")
}
