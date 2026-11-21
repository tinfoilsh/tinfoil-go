package tinfoil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// embeddedRepoPin embeds a variant, so it has the variant's methods without
// being one.
type embeddedRepoPin struct{ RepoPin }

func testKeys(t *testing.T) []crypto.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return []crypto.PublicKey{key.Public()}
}

func TestTrustSelectsConfigTrustAndPin(t *testing.T) {
	keys := testKeys(t)
	authorize := func(collateral.ConfigEndorsement) error { return nil }
	for name, tc := range map[string]struct {
		trust  Trust
		config verify.ConfigTrust
		pin    verify.Pin
	}{
		"repository":                     {RepoPin{Repo: "org/repo"}, nil, verify.Pin{Repo: "org/repo"}},
		"project in the public registry": {ProjectPin{Project: "org/project"}, nil, verify.Pin{Project: "org/project"}},
		"project in listed registries": {
			ProjectPin{Project: "org/project", RegistryIDs: []string{verify.PublicRegistryID}},
			verify.Registries{IDs: []string{verify.PublicRegistryID}}, verify.Pin{Project: "org/project"},
		},
		"signing keys":               {SignedBy{Keys: keys}, verify.ConfigSigningKeys{Keys: keys}, verify.Pin{}},
		"signing keys for a project": {SignedBy{Keys: keys, Project: "org/project"}, verify.ConfigSigningKeys{Keys: keys}, verify.Pin{Project: "org/project"}},
		"embedded config":            {EmbeddedConfig{Name: "/org/project/v1", Bytes: []byte("config")}, verify.EmbeddedConfig{Name: "/org/project/v1", Bytes: []byte("config")}, verify.Pin{}},
		"either pin":                 {EitherPin{Repo: "org/repo", Project: "org/project"}, nil, verify.Pin{Repo: "org/repo", Project: "org/project"}},
	} {
		t.Run(name, func(t *testing.T) {
			config, pin, err := verifierInputs(tc.trust)
			require.NoError(t, err)
			require.Equal(t, tc.config, config)
			require.Equal(t, tc.pin, pin)
		})
	}

	config, pin, err := verifierInputs(AuthorizedBy{Authorize: authorize})
	require.NoError(t, err)
	require.IsType(t, verify.ConfigAuthorizer{}, config, "functions can't be compared")
	require.NotNil(t, config.(verify.ConfigAuthorizer).Authorize)
	require.Equal(t, verify.Pin{}, pin, "approval authenticates no name, so there is no pin")
}

// The verifier reports an authorizer's refusal as a provenance failure, an
// attestation error, so that a category in the authorizer's error is not
// kept.
func TestAnAuthorizersErrorCarriesNoCategory(t *testing.T) {
	cause := errors.New("config is not authorized")
	for _, returned := range []error{cause, errs.Network(cause), errs.Configuration(cause)} {
		config, _, err := verifierInputs(AuthorizedBy{Authorize: func(collateral.ConfigEndorsement) error { return returned }})
		require.NoError(t, err)
		got := config.(verify.ConfigAuthorizer).Authorize(collateral.ConfigEndorsement{})
		require.ErrorIs(t, got, cause)
		require.Equal(t, returned.Error(), got.Error())
		testutil.RequireCategory(t, errs.Attestation(&verify.VerificationError{Layer: verify.LayerProvenance, Err: got}), ErrAttestation)
	}
	config, _, err := verifierInputs(AuthorizedBy{Authorize: func(collateral.ConfigEndorsement) error { return nil }})
	require.NoError(t, err)
	require.NoError(t, config.(verify.ConfigAuthorizer).Authorize(collateral.ConfigEndorsement{}))
}

// Each variant's own requirements fail before any network I/O, and so does a
// value that the verifier rejects.
func TestInvalidTrustIsAConfigurationError(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("invalid trust sent %s %s", req.Method, req.URL)
		return nil, errors.New("no network in this test")
	})
	for name, tc := range map[string]struct {
		trust Trust
		usage bool // the verifier reports it, as the cause
	}{
		"nil":                             {nil, false},
		"pointer to a variant":            {&RepoPin{Repo: "org/repo"}, false},
		"type that embeds a variant":      {embeddedRepoPin{RepoPin{Repo: "org/repo"}}, false},
		"empty repository":                {RepoPin{}, false},
		"empty project":                   {ProjectPin{}, false},
		"empty but non-nil registry IDs":  {ProjectPin{Project: "org/project", RegistryIDs: []string{}}, false},
		"either pin without a project":    {EitherPin{Repo: "org/repo"}, false},
		"either pin without a repository": {EitherPin{Project: "org/project"}, false},
		"malformed repository":            {RepoPin{Repo: "not a reference"}, true},
		"malformed project":               {ProjectPin{Project: "not a reference"}, true},
		"malformed registry ID":           {ProjectPin{Project: "org/project", RegistryIDs: []string{"not a registry"}}, true},
		"no signing keys":                 {SignedBy{Project: "org/project"}, true},
		"malformed signed project":        {SignedBy{Keys: testKeys(t), Project: "not a reference"}, true},
		"no authorizer":                   {AuthorizedBy{}, true},
		"no embedded config":              {EmbeddedConfig{Name: "/org/project/v1"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewEnclaveHTTPClient(t.Context(), "enclave.example", tc.trust, nil)
			require.Nil(t, c)
			require.ErrorIs(t, err, ErrConfiguration)
			var usage *verify.UsageError
			require.Equal(t, tc.usage, errors.As(err, &usage), "%v", err)
		})
	}
}

func TestValidTrustBuildsAClient(t *testing.T) {
	for name, trust := range map[string]Trust{
		"repository":                     RepoPin{Repo: "org/repo@v1"},
		"project in the public registry": ProjectPin{Project: "org/project@v1"},
		"project in listed registries":   ProjectPin{Project: "org/project", RegistryIDs: []string{verify.PublicRegistryID}},
		"signing keys":                   SignedBy{Keys: testKeys(t)},
		"signing keys for a project":     SignedBy{Keys: testKeys(t), Project: "org/project"},
		"authorizer":                     AuthorizedBy{Authorize: func(collateral.ConfigEndorsement) error { return nil }},
		"either pin":                     EitherPin{Repo: "org/repo", Project: "org/project"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := unverifiedEnclaveHTTPClient("enclave.example", trust, nil)
			require.NoError(t, err)
		})
	}
}
