package tdx

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	tdxtesting "github.com/google/go-tdx-guest/testing"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// jsonEscape replaces each %XX in s with the JSON escape for the byte 0xXX.
func jsonEscape(s string) string {
	return strings.ReplaceAll(s, "%", `\`+"u00")
}

func TestCheckSignedCollateralBody(t *testing.T) {
	const tcbURL = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
	const qeURL = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	for _, tt := range []struct {
		name, url, body, wantError string
	}{
		{"TCB Info", tcbURL, `{"tcbInfo":{},"signature":"00"}`, ""},
		{"QE Identity", qeURL, `{"signature":"00","enclaveIdentity":{}}`, ""},
		{"not a PCS JSON response", "https://example.com/crl", `not json`, ""},
		{"case variant after the signed member", tcbURL, `{"tcbInfo":{},"signature":"00","TcbInfo":{}}`, "exactly"},
		{"case variant before the signed member", tcbURL, `{"TCBINFO":{},"tcbInfo":{},"signature":"00"}`, "exactly"},
		{"case variant of the signature", qeURL, `{"enclaveIdentity":{},"signature":"00","Signature":"01"}`, "exactly"},
		{"unknown member", qeURL, `{"enclaveIdentity":{},"signature":"00","extra":1}`, "exactly"},
		{"case variant in place of the signed member", qeURL, `{"EnclaveIdentity":{},"signature":"00"}`, "exactly"},
		{"missing signature", tcbURL, `{"tcbInfo":{}}`, "exactly"},
		{"exact duplicate", tcbURL, `{"tcbInfo":{},"tcbInfo":{},"signature":"00"}`, "duplicate"},
		{"escaped duplicate", tcbURL, jsonEscape(`{"tcbInfo":{},"tcb%49nfo":{},"signature":"00"}`), "duplicate"},
		{"escaped case variant", tcbURL, jsonEscape(`{"tcbInfo":{},"signature":"00","%54cbInfo":{}}`), "exactly"},
		{"escaped signed member", tcbURL, jsonEscape(`{"%74cbInfo":{},"signature":"00"}`), ""},
		{"not an object", tcbURL, `[]`, "parsing"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSignedCollateralBody(tt.url, []byte(tt.body))
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantError)
			}
		})
	}
}

// Intel's signed sample collateral with an extra top-level member is refused
// before it reaches the library.
func TestAuthenticateRejectsUnsignedCollateralMembers(t *testing.T) {
	const (
		tcbURL    = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
		qeURL     = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
		pckCRLURL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
		rootURL   = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
	)
	// The sample quote carries trailing bytes after the signed data, which
	// Authenticate rejects; they are unsigned, so drop them.
	signedDataSize := binary.LittleEndian.Uint32(tdxtestdata.RawQuote[0x278:0x27C])
	quote := tdxtestdata.RawQuote[:0x27C+int(signedDataSize)]
	authenticate := func(now time.Time, tcbBody, qeBody []byte) error {
		_, err := Authenticate(Evidence{Quote: quote, PCS: []collateral.PCSResponse{
			{URL: tcbURL, Headers: tdxtesting.TcbInfoHeader, Body: tcbBody},
			{URL: qeURL, Headers: tdxtesting.QeIdentityHeader, Body: qeBody},
			{URL: pckCRLURL, Headers: tdxtesting.PckCrlHeader, Body: tdxtestdata.PckCrlBody},
			{URL: rootURL, Body: tdxtestdata.RootCrlBody},
		}}, now, nil)
		return err
	}
	appendMember := func(body []byte, member string) []byte {
		s := strings.TrimSpace(string(body))
		require.True(t, strings.HasSuffix(s, "}"))
		return []byte(s[:len(s)-1] + "," + member + "}")
	}
	tcb, qe := tdxtestdata.TcbInfoBody, tdxtestdata.QeIdentityBody
	zeroSVNs := `[` + strings.Repeat(`{"svn":0},`, 15) + `{"svn":0}]`
	upToDate := `"TcbInfo":{"tcbLevels":[{"tcb":{"sgxtcbcomponents":` + zeroSVNs + `,"pcesvn":0,"tdxtcbcomponents":` + zeroSVNs + `},"tcbDate":"2099-01-01T00:00:00Z","tcbStatus":"UpToDate"}]}`

	// Within the sample's validity window, Intel's signed TCB Info has no
	// level that this platform satisfies.
	inWindow := time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
	require.ErrorContains(t, authenticate(inWindow, tcb, qe), "no matching TCB level")
	assert.ErrorContains(t, authenticate(inWindow, appendMember(tcb, upToDate), qe), `exactly the "tcbInfo" and "signature" members`)

	// After the QE Identity's nextUpdate but before the PCK CRL's.
	qeExpired := time.Date(2023, time.July, 8, 7, 26, 0, 0, time.UTC)
	require.ErrorContains(t, authenticate(qeExpired, tcb, qe), "QeIdentity has expired")
	assert.ErrorContains(t, authenticate(qeExpired, tcb, appendMember(qe, `"EnclaveIdentity":{"nextUpdate":"2099-01-01T00:00:00Z"}`)), `exactly the "enclaveIdentity" and "signature" members`)
}
