package enclave

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestClientOptionsCopyPinnedRegisters(t *testing.T) {
	register := strings.Repeat("ab", 48)
	pins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}
	opts := Options{PinnedRegisters: pins, FreshnessMaxAge: time.Hour}
	first, err := NewHandle("enclave.example", "org/repo", &opts)
	require.NoError(t, err)
	second, err := NewHandle("enclave.example", "org/repo", &opts)
	require.NoError(t, err)

	// Mutating the caller's options and measurement after construction must
	// not reach either client. That the accessor also copies on the way out is
	// the verifier package's contract, covered by its own tests.
	opts.FreshnessMaxAge = time.Minute
	pins.Type = measurement.SevGuestV2
	pins.Registers[4] = "changed"
	assert.Equal(t, measurement.TdxGuestV2, first.verifier.PinnedRegisters().Type)
	assert.Equal(t, register, first.verifier.PinnedRegisters().Registers[4])
	assert.Equal(t, register, second.verifier.PinnedRegisters().Registers[4])
	assert.Equal(t, time.Hour, second.verifier.FreshnessMaxAge())
}

func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	enclave := os.Getenv(enclaveEnvVar)
	repo := os.Getenv(repoEnvVar)

	client, err := NewHandle(enclave, repo, nil)
	require.NoError(t, err)
	_, err = client.Verify()
	assert.NoError(t, err)
}

func TestClientVerificationJSON(t *testing.T) {
	codeMeasurement := &measurement.Measurement{
		Type:      measurement.SnpTdxMultiPlatformV1,
		Registers: []string{"a", "b"},
	}
	enclaveMeasurement := &measurement.Measurement{
		Type:      measurement.TdxGuestV2,
		Registers: []string{"a"},
	}

	verified := &verify.Verification{
		CodeDigest:         "feabcd",
		CryptoMaterial:     testState(time.Time{}, "key").CryptoMaterial,
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveMeasurement,
	}
	client := &Handle{
		state: &enclaveState{Verification: verified},
	}

	encoded, err := client.VerificationJSON()
	assert.NoError(t, err)

	var decoded verify.Verification
	assert.NoError(t, json.Unmarshal([]byte(encoded), &decoded))
	assert.Equal(t, verified, &decoded)
	view := client.Verification()
	view.CodeMeasurement.Registers[0] = "changed"
	view.CryptoMaterial[0].Data = "changed"
	view.EnclaveMeasurement.Registers[0] = "changed"
	assert.Equal(t, &decoded, client.Verification(), "returned measurements must not alias cached verification")
}

func TestLiveNewDefaultHandle(t *testing.T) {
	testutil.RequireLive(t)
	client, err := NewDefaultHandle(nil)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	enclave := client.Enclave()
	assert.NotEmpty(t, enclave)

	_, err = client.Verify()
	assert.NoError(t, err)
}

func TestLiveClientFetchRouters(t *testing.T) {
	testutil.RequireLive(t)
	routers, err := fetchRouters()
	require.NoError(t, err)
	require.NotEmpty(t, routers)
	assert.True(t, strings.HasSuffix(routers[0], ".tinfoil.sh"))
}

func TestLiveClientFallbackEnclave(t *testing.T) {
	testutil.RequireLive(t)
	defaultClient, err := NewHandle("inference.tinfoil.sh", defaultRouterRepo, nil)
	require.NoError(t, err)
	enclave := defaultClient.Enclave()
	assert.NotEmpty(t, enclave)

	_, err = defaultClient.Verify()
	assert.NoError(t, err)
}

func TestHandleReportsSDKIdentity(t *testing.T) {
	requests := make(chan *http.Request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()
	original := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = original })

	swift := verify.SoftwareIdentity{Name: "tinfoil-swift", Version: "0.8.2"}
	h, err := NewHandle(strings.TrimPrefix(server.URL, "https://"), "org/repo", &Options{SDK: &swift})
	require.NoError(t, err)
	require.Equal(t, swift, h.verifier.Identity())
	_, err = h.fetchVerification()
	require.Error(t, err, "the stub serves no valid document")
	request := <-requests
	require.Equal(t, "tinfoil-swift", request.Header.Get("Tinfoil-SDK"))
	require.Equal(t, "0.8.2", request.Header.Get("Tinfoil-SDK-Version"))
}
