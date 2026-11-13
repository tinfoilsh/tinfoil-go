package mobile

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// recordingAuthorizer stands in for a Swift implementation.
type recordingAuthorizer struct {
	mu       sync.Mutex
	payloads []string
	err      error
}

func (a *recordingAuthorizer) AuthorizeConfig(endorsementJSON string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.payloads = append(a.payloads, endorsementJSON)
	return a.err
}

func TestNewVerifierWithConfigAuthorizer(t *testing.T) {
	verifier, err := NewVerifierWithConfigAuthorizer("", &recordingAuthorizer{})
	require.NoError(t, err)
	assert.True(t, verifier.inner.CallerAuthorizesConfig())

	plain, err := NewVerifier("")
	require.NoError(t, err)
	assert.False(t, plain.inner.CallerAuthorizesConfig())
}

func TestNewVerifierWithConfigAuthorizerRejects(t *testing.T) {
	key := testKeyPEM(t)
	for _, tc := range []struct {
		name, options, contains string
		authorizer              ConfigAuthorizer
	}{
		{"nil authorizer", "", "must not be nil", nil},
		{"with config signing keys", `{"config_signing_keys_pem":[` + quoted(key) + `]}`, "config authorizer conflicts", &recordingAuthorizer{}},
		{"with an embedded config", `{"embedded_config":{"bytes":"` + b64(testConfig) + `"}}`, "config authorizer conflicts", &recordingAuthorizer{}},
		{"with registry IDs", `{"config_registry_ids":[` + quoted(PublicRegistryID) + `]}`, "require endorsement verification", &recordingAuthorizer{}},
		{"with malformed options", `{"unknown":1}`, "parsing verification options", &recordingAuthorizer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifierWithConfigAuthorizer(tc.options, tc.authorizer)
			requireUsageError(t, err, tc.contains)
		})
	}
}

// The authorizer sees the document's config material as JSON, with only the
// members the document carries.
func TestAuthorizerPayload(t *testing.T) {
	for _, tc := range []struct {
		name        string
		endorsement collateral.ConfigEndorsement
		want        map[string]any
	}{
		{
			"plain config",
			collateral.ConfigEndorsement{Config: []byte("cvm-version: x")},
			map[string]any{"config": b64("cvm-version: x")},
		},
		{
			"certified config",
			collateral.ConfigEndorsement{Config: []byte("c"), Reference: "sha256:ab", Bundle: jsontext.Value(`{"k":1}`), Issuer: []byte{1, 2}},
			map[string]any{"config": b64("c"), "reference": "sha256:ab", "sigstore_bundle": map[string]any{"k": float64(1)}, "issuer_certificate_der": "AQI="},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := &recordingAuthorizer{}
			require.NoError(t, authorizeWith(authorizer)(tc.endorsement))
			require.Len(t, authorizer.payloads, 1)
			var got map[string]any
			require.NoError(t, json.Unmarshal([]byte(authorizer.payloads[0]), &got))
			assert.Equal(t, tc.want, got)
		})
	}
}

// A rejection is returned to the verifier as is, which reports it at the
// provenance layer.
func TestAuthorizerRejectionPassesThrough(t *testing.T) {
	rejected := errors.New("config not allowed")
	err := authorizeWith(&recordingAuthorizer{err: rejected})(collateral.ConfigEndorsement{Config: []byte("c")})
	assert.ErrorIs(t, err, rejected)
}

// The checks a client makes before any I/O are reachable through the binding.
func TestRepoChecksBeforeIO(t *testing.T) {
	authorized, err := NewVerifierWithConfigAuthorizer("", &recordingAuthorizer{})
	require.NoError(t, err)
	assert.True(t, authorized.CallerAuthorizesConfig())
	assert.NoError(t, authorized.CheckRepoVerifiability(""))
	requireUsageError(t, authorized.CheckRepoVerifiability("org/repo"), "config authorizer cannot authenticate")

	embedded, err := NewVerifier(`{"embedded_config":{"name":"/org/project/v1","bytes":"` + b64(testConfig) + `"}}`)
	require.NoError(t, err)
	assert.True(t, embedded.CallerAuthorizesConfig())
	assert.NoError(t, embedded.CheckRepoVerifiability("org/project@v1"))
	requireUsageError(t, embedded.CheckRepoVerifiability("org/other"), "does not match")

	defaults, err := NewVerifier("")
	require.NoError(t, err)
	assert.False(t, defaults.CallerAuthorizesConfig())
	assert.NoError(t, defaults.CheckRepoVerifiability(routerRepo))
	requireUsageError(t, defaults.CheckRepoVerifiability("not a reference"), "")
}
