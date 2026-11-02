package enclave

import (
	"net/http"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

const (
	enclaveEnvVar = "TINFOIL_ENCLAVE"
	repoEnvVar    = "TINFOIL_REPO"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testState(deadline time.Time, key string) *verify.Verification {
	return verifytest.New(verifytest.Fields{
		CodeTag: key, FreshnessExpiresAt: deadline,
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: key},
			{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: key},
		},
	})
}

func testResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
}
