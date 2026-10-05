package mobile

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const swiftOptions = `{"sdk":{"name":"tinfoil-swift","version":"0.8.2"}}`

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// network stands in for http.DefaultClient, which the SDK fetches router lists
// and attestation through, and records what was sent.
type network struct {
	mu       sync.Mutex
	requests []*http.Request
}

func stubNetwork(t *testing.T, respond func(*http.Request) (*http.Response, error)) *network {
	t.Helper()
	n := &network{}
	original := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n.mu.Lock()
		n.requests = append(n.requests, r)
		n.mu.Unlock()
		return respond(r)
	})}
	t.Cleanup(func() { http.DefaultClient = original })
	return n
}

func (n *network) sent() []*http.Request {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*http.Request(nil), n.requests...)
}

func unavailable(*http.Request) (*http.Response, error) { return nil, errors.New("unavailable") }

// Swift tells error categories apart by prefix alone, so the exported prefixes
// must be the ones the SDK's error types produce.
func TestErrorPrefixesMatchCategories(t *testing.T) {
	cause := errors.New("cause")
	for prefix, err := range map[string]error{
		ConfigurationErrorPrefix: &verify.ConfigurationError{Err: cause},
		FetchErrorPrefix:         &verify.FetchError{Err: cause},
		AttestationErrorPrefix:   &verify.AttestationError{Err: cause},
	} {
		assert.Equal(t, prefix+"cause", err.Error())
	}
}

// A relayed client must send every attestation fetch to the relay, name the
// enclave it is for, and keep the options it was derived with.
func TestViaRelayFetchesAttestationThroughRelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		network := stubNetwork(t, unavailable)
		client, err := NewClientWithOptions("enclave.example", "org/repo", swiftOptions)
		require.NoError(t, err)

		relayed := client.ViaRelay("relay.example:8443")
		assert.Equal(t, "enclave.example", relayed.Enclave())
		assert.Equal(t, "org/repo", relayed.Repo())
		_, err = relayed.Verify()
		require.ErrorContains(t, err, "unavailable")

		requests := network.sent()
		require.NotEmpty(t, requests)
		for _, r := range requests {
			assert.Equal(t, "https", r.URL.Scheme)
			assert.Equal(t, "relay.example:8443", r.URL.Host)
			assert.Equal(t, "enclave.example", r.URL.Query().Get("enclave"))
			assert.Equal(t, "tinfoil-swift", r.Header.Get("Tinfoil-SDK"))
		}
	})
}

// When no discovered router verifies, the client falls back to the default
// host without having verified it, so a caller must not expect a cached result.
func TestNewDefaultClientFallsBackUnverified(t *testing.T) {
	network := stubNetwork(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "atc.tinfoil.sh" {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`["router.example"]`))}, nil
		}
		return nil, errors.New("unavailable")
	})
	client, err := NewDefaultClient(swiftOptions)
	require.NoError(t, err)
	assert.Equal(t, "inference.tinfoil.sh", client.Enclave())
	assert.Equal(t, "tinfoilsh/confidential-model-router", client.Repo())
	cached, err := client.Verification()
	require.NoError(t, err)
	assert.Empty(t, cached)

	var probed bool
	for _, r := range network.sent() {
		if r.URL.Host == "router.example" {
			probed = true
			assert.Equal(t, "tinfoil-swift", r.Header.Get("Tinfoil-SDK"), "options apply to discovered routers")
		}
	}
	assert.True(t, probed, "the discovered router was tried")
}

func TestNewDefaultClientRejectsOptionsBeforeDiscovery(t *testing.T) {
	network := stubNetwork(t, unavailable)
	_, err := NewDefaultClient(`{"freshness_max_age_ns":-1}`)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), ConfigurationErrorPrefix), err.Error())
	assert.Empty(t, network.sent())
}

// Request errors reach Swift as text, so each must still lead with its category.
func TestRequestErrorsLeadWithCategory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stubNetwork(t, unavailable)
		client, err := NewClient("enclave.example", "org/repo")
		require.NoError(t, err)

		_, err = client.Request("GET", "/", "not json", nil)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), ConfigurationErrorPrefix), err.Error())

		_, err = client.Request("GET", "/", "", nil)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), FetchErrorPrefix), err.Error())
	})
}

func TestLiveNewDefaultClient(t *testing.T) {
	testutil.RequireLive(t)
	client, err := NewDefaultClient(swiftOptions)
	require.NoError(t, err)
	payload, err := client.Verification()
	require.NoError(t, err)
	if payload == "" {
		payload, err = client.Verify()
		require.NoError(t, err)
	}

	var got verificationJSON
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	assert.Equal(t, client.Enclave(), got.EnclaveHost)
	assert.NotEmpty(t, got.HPKEPublicKey)
	assert.Equal(t, softwareIdentityJSON{Name: "tinfoil-swift", Version: "0.8.2"}, got.Verifier)
}
