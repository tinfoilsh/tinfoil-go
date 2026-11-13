package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A config, the runtime manifest it pins, and an empty platform policy: the
// smallest embedded references the verifier accepts.
var (
	testRuntime  = `{"version":"v0.15.0","igvm":{"format_version":1,"snp_launch":{"measurement":"` + strings.Repeat("ab", 48) + `"},"tdx_launch":{"mrtd":"` + strings.Repeat("cd", 48) + `","rtmr0":"` + strings.Repeat("00", 48) + `","rtmr1":"` + strings.Repeat("00", 48) + `","rtmr2":"` + strings.Repeat("00", 48) + `","rtmr3":"` + strings.Repeat("00", 48) + `"}}}`
	testPlatform = `{"format":"https://tinfoil.sh/predicate/platform-endorsements/v2","machines":{},"policies":{}}`
	testConfig   = fmt.Sprintf("cvm-version: 0.15.0@sha256:%x\n", sha256.Sum256([]byte(testRuntime)))
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func testKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func quoted(s string) string {
	encoded, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func requireUsageError(t *testing.T, err error, contains string) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), UsageErrorPrefix), err.Error())
	assert.Contains(t, err.Error(), contains)
}

func TestNewVerifierAcceptsTrustOptions(t *testing.T) {
	key := quoted(testKeyPEM(t))
	digest := sha256.Sum256([]byte(testConfig))
	configReference := `{"name":"/org/project/v1","digest":"` + hex.EncodeToString(digest[:]) +
		`","runtime":{"repo":"tinfoilsh/cvmimage","tag":"v0.15.0","digest":"` + fmt.Sprintf("%x", sha256.Sum256([]byte(testRuntime))) + `"}}`
	for _, tc := range []struct {
		name             string
		options          string
		authorizesConfig bool
	}{
		{"null members keep the defaults", `{"config_registry_ids":null,"embedded_config":null,"embedded_runtime":null}`, false},
		{"registry IDs", `{"config_registry_ids":[` + quoted(PublicRegistryID) + `]}`, false},
		{"config signing keys", `{"config_signing_keys_pem":[` + key + `]}`, false},
		{"freshness signing keys", `{"freshness_signing_keys_pem":[` + key + `]}`, false},
		{"embedded config bytes", `{"embedded_config":{"name":"/org/project/v1","bytes":"` + b64(testConfig) + `"}}`, true},
		{"embedded config reference", `{"embedded_config":` + configReference + `}`, true},
		{"embedded runtime and platform", `{"embedded_runtime":"` + b64(testRuntime) + `","embedded_platform":"` + b64(testPlatform) + `"}`, false},
		{"every embedded component", `{"embedded_config":{"bytes":"` + b64(testConfig) + `"},"embedded_runtime":"` + b64(testRuntime) + `","embedded_platform":"` + b64(testPlatform) + `"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := NewVerifier(tc.options)
			require.NoError(t, err)
			assert.Equal(t, tc.authorizesConfig, verifier.inner.CallerAuthorizesConfig())
		})
	}
}

// Each option reaches the verifier: the verifier's own checks, including the
// conflicts between trust sources, reject what the options parser lets
// through.
func TestNewVerifierRejectsTrustOptions(t *testing.T) {
	key := testKeyPEM(t)
	for _, tc := range []struct {
		name, options, contains string
	}{
		{"empty registry IDs", `{"config_registry_ids":[]}`, "must not be empty"},
		{"malformed registry ID", `{"config_registry_ids":["not a registry"]}`, "canonical registry URI"},
		{"registry IDs with signing keys", `{"config_registry_ids":[` + quoted(PublicRegistryID) + `],"config_signing_keys_pem":[` + quoted(key) + `]}`, "registry ID policy"},
		{"embedded config with signing keys", `{"embedded_config":{"bytes":"` + b64(testConfig) + `"},"config_signing_keys_pem":[` + quoted(key) + `]}`, "conflicting trust sources"},
		{"freshness keys with nothing endorsed", `{"embedded_config":{"bytes":"` + b64(testConfig) + `"},"embedded_runtime":"` + b64(testRuntime) + `","embedded_platform":"` + b64(testPlatform) + `","freshness_signing_keys_pem":[` + quoted(key) + `]}`, "no endorsed artifact"},
		{"empty signing keys", `{"config_signing_keys_pem":[]}`, "must not be empty"},
		{"text before the key", `{"config_signing_keys_pem":[` + quoted("junk\n"+key) + `]}`, "PEM PUBLIC KEY block"},
		{"two keys in one entry", `{"config_signing_keys_pem":[` + quoted(key+key) + `]}`, "single PEM block"},
		{"wrong block type", `{"config_signing_keys_pem":[` + quoted(strings.ReplaceAll(key, "PUBLIC KEY", "CERTIFICATE")) + `]}`, "PEM PUBLIC KEY block"},
		{"not a key", `{"config_signing_keys_pem":[` + quoted(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("nope")}))) + `]}`, "config signing key 0"},
		{"embedded config with bytes and digest", `{"embedded_config":{"bytes":"` + b64(testConfig) + `","digest":"` + strings.Repeat("ab", 32) + `"}}`, "either bytes, or digest and runtime"},
		{"embedded config with digest only", `{"embedded_config":{"digest":"` + strings.Repeat("ab", 32) + `"}}`, "either bytes, or digest and runtime"},
		{"empty embedded config", `{"embedded_config":{}}`, "either bytes, or digest and runtime"},
		{"empty embedded config bytes", `{"embedded_config":{"bytes":""}}`, "must not be empty"},
		{"unpadded base64", `{"embedded_runtime":"` + strings.TrimRight(b64(testRuntime+"x"), "=") + `"}`, "embedded_runtime"},
		{"malformed config", `{"embedded_config":{"bytes":"` + b64("not: a config") + `"}}`, "cvm-version"},
		{"runtime the config does not pin", `{"embedded_config":{"bytes":"` + b64(testConfig) + `"},"embedded_runtime":"` + b64(strings.Replace(testRuntime, "v0.15.0", "v0.15.1", 1)) + `"}`, "does not match"},
		{"unknown embedded member", `{"embedded_config":{"bytes":"` + b64(testConfig) + `","extra":1}}`, "parsing verification options"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(tc.options)
			requireUsageError(t, err, tc.contains)
		})
	}
}
