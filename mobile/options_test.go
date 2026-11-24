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
	testRuntime  = `{"version":"v0.15.5","igvm":{"format_version":1,"snp_launch":{"measurement":"` + strings.Repeat("ab", 48) + `"},"tdx_launch":{"mrtd":"` + strings.Repeat("cd", 48) + `","rtmr0":"` + strings.Repeat("00", 48) + `","rtmr1":"` + strings.Repeat("00", 48) + `","rtmr2":"` + strings.Repeat("00", 48) + `","rtmr3":"` + strings.Repeat("00", 48) + `"}}}`
	testPlatform = `{"format":"https://tinfoil.sh/predicate/platform-endorsements/v2","machines":{},"policies":{}}`
	testConfig   = fmt.Sprintf(`{"cvm-version":"0.15.5@sha256:%x"}`, sha256.Sum256([]byte(testRuntime)))
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

// Shorthands for the tagged objects, so that the cases below read as options.
func withConfigTrust(members string) string { return `{"config_trust":{` + members + `}}` }
func withArtifacts(members string) string   { return `{"policy":{"artifacts":{` + members + `}}}` }

func TestNewVerifierAcceptsTrustOptions(t *testing.T) {
	key := quoted(testKeyPEM(t))
	digest := sha256.Sum256([]byte(testConfig))
	configReference := `"type":"embedded_config_reference","name":"/org/project/v1","digest":"` + hex.EncodeToString(digest[:]) +
		`","runtime":{"repo":"tinfoilsh/cvmimage","tag":"v0.15.5","digest":"` + fmt.Sprintf("%x", sha256.Sum256([]byte(testRuntime))) + `"}`
	embeddedArtifacts := `"type":"embedded","runtime":"` + b64(testRuntime) + `","platform":"` + b64(testPlatform) + `"`
	for _, tc := range []struct {
		name             string
		options          string
		authorizesConfig bool
	}{
		{"empty object", `{}`, false},
		{"null members keep the defaults", `{"config_trust":null,"policy":null}`, false},
		{"null policy members keep the defaults", `{"policy":{"pinned_registers":null,"artifacts":null}}`, false},
		{"registry IDs", withConfigTrust(`"type":"registries","ids":[` + quoted(PublicRegistryID) + `]`), false},
		{"config signing keys", withConfigTrust(`"type":"signing_keys","keys_pem":[` + key + `]`), false},
		{"endorsed artifacts", withArtifacts(`"type":"endorsed"`), false},
		{"freshness signing keys", withArtifacts(`"type":"endorsed","freshness_keys_pem":[` + key + `]`), false},
		{"embedded config bytes", withConfigTrust(`"type":"embedded_config","name":"/org/project/v1","bytes":"` + b64(testConfig) + `"`), true},
		{"embedded config reference", withConfigTrust(configReference), true},
		{"embedded runtime and platform", withArtifacts(embeddedArtifacts), false},
		{"embedded runtime with freshness keys", withArtifacts(`"type":"embedded","runtime":"` + b64(testRuntime) + `","freshness_keys_pem":[` + key + `]`), false},
		{"every embedded component", `{"config_trust":{"type":"embedded_config","bytes":"` + b64(testConfig) + `"},"policy":{"artifacts":{` + embeddedArtifacts + `}}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := NewVerifier(tc.options)
			require.NoError(t, err)
			assert.Equal(t, tc.authorizesConfig, verifier.CallerAuthorizesConfig())
		})
	}
}

// Each option reaches the verifier, whose own checks reject what the options
// parser lets through.
func TestNewVerifierRejectsTrustOptions(t *testing.T) {
	key := testKeyPEM(t)
	for _, tc := range []struct {
		name, options, contains string
	}{
		{"missing registry IDs", withConfigTrust(`"type":"registries"`), "must not be empty"},
		{"empty registry IDs", withConfigTrust(`"type":"registries","ids":[]`), "must not be empty"},
		{"malformed registry ID", withConfigTrust(`"type":"registries","ids":["not a registry"]`), "canonical registry URI"},
		{"freshness keys with nothing endorsed", `{"config_trust":{"type":"embedded_config","bytes":"` + b64(testConfig) + `"},"policy":{"artifacts":{"type":"embedded","runtime":"` + b64(testRuntime) + `","platform":"` + b64(testPlatform) + `","freshness_keys_pem":[` + quoted(key) + `]}}}`, "no endorsed artifact"},
		{"embedded artifacts with nothing embedded", withArtifacts(`"type":"embedded"`), ""},
		{"empty freshness keys", withArtifacts(`"type":"endorsed","freshness_keys_pem":[]`), "must not be empty"},
		{"missing signing keys", withConfigTrust(`"type":"signing_keys"`), "must not be empty"},
		{"empty signing keys", withConfigTrust(`"type":"signing_keys","keys_pem":[]`), "must not be empty"},
		{"text before the key", withConfigTrust(`"type":"signing_keys","keys_pem":[` + quoted("junk\n"+key) + `]`), "PEM PUBLIC KEY block"},
		{"two keys in one entry", withConfigTrust(`"type":"signing_keys","keys_pem":[` + quoted(key+key) + `]`), "single PEM block"},
		{"wrong block type", withConfigTrust(`"type":"signing_keys","keys_pem":[` + quoted(strings.ReplaceAll(key, "PUBLIC KEY", "CERTIFICATE")) + `]`), "PEM PUBLIC KEY block"},
		{"not a key", withConfigTrust(`"type":"signing_keys","keys_pem":[` + quoted(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("nope")}))) + `]`), "config signing key 0"},
		{"not a freshness key", withArtifacts(`"type":"endorsed","freshness_keys_pem":["nope"]`), "freshness signing key 0"},
		{"embedded config without bytes", withConfigTrust(`"type":"embedded_config"`), "must not be empty"},
		{"empty embedded config bytes", withConfigTrust(`"type":"embedded_config","bytes":""`), "must not be empty"},
		{"config reference with digest only", withConfigTrust(`"type":"embedded_config_reference","digest":"` + strings.Repeat("ab", 32) + `"`), "runtime"},
		{"config reference without digest", withConfigTrust(`"type":"embedded_config_reference","runtime":{"repo":"tinfoilsh/cvmimage","tag":"v0.15.0","digest":"` + strings.Repeat("ab", 32) + `"}`), "config digest"},
		{"empty embedded runtime", withArtifacts(`"type":"embedded","runtime":""`), "must not be empty"},
		{"unpadded base64", withArtifacts(`"type":"embedded","runtime":"` + strings.TrimRight(b64(testRuntime+"x"), "=") + `"`), "artifacts.runtime"},
		{"malformed config", withConfigTrust(`"type":"embedded_config","bytes":"` + b64("not: a config") + `"`), "cvm-version"},
		{"YAML config", withConfigTrust(`"type":"embedded_config","bytes":"` + b64(fmt.Sprintf("cvm-version: 0.15.4@sha256:%x\n", sha256.Sum256([]byte(testRuntime)))) + `"`), "must be a JSON config"},
		{"runtime the config does not pin", `{"config_trust":{"type":"embedded_config","bytes":"` + b64(testConfig) + `"},"policy":{"artifacts":{"type":"embedded","runtime":"` + b64(strings.Replace(testRuntime, "v0.15.5", "v0.15.6", 1)) + `"}}}`, "does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(tc.options)
			requireUsageError(t, err, tc.contains)
		})
	}
}

// The parser rejects anything that is not exactly one of the documented
// shapes, before the verifier sees it.
func TestNewVerifierRejectsMalformedOptions(t *testing.T) {
	for _, tc := range []struct {
		name, options, contains string
	}{
		{"malformed JSON", `{"config_trust":`, "parsing verification options"},
		{"not an object", `[]`, "parsing verification options"},
		{"null", `null`, "must be a JSON object"},
		{"unknown member", `{"enclave":"x"}`, "parsing verification options"},
		{"former flat member", `{"config_registry_ids":["x"]}`, "parsing verification options"},
		{"duplicate member", `{"policy":{},"policy":{}}`, "duplicate object member"},
		{"unknown policy member", `{"policy":{"embedded_runtime":"eA=="}}`, "parsing verification options"},
		{"policy not an object", `{"policy":"x"}`, "parsing verification options"},
		{"config trust not an object", `{"config_trust":["registries"]}`, "parsing config_trust"},
		{"config trust without a type", withConfigTrust(`"ids":["x"]`), "config_trust requires a type"},
		{"config trust type not a string", withConfigTrust(`"type":1`), "parsing config_trust"},
		{"unknown config trust type", withConfigTrust(`"type":"authorizer"`), `unknown type "authorizer"`},
		{"duplicate type", withConfigTrust(`"type":"registries","type":"signing_keys"`), "duplicate object member"},
		{"duplicate member in a tagged object", withConfigTrust(`"type":"registries","ids":[],"ids":[]`), "duplicate object member"},
		{"member of another config trust type", withConfigTrust(`"type":"registries","ids":[` + quoted(PublicRegistryID) + `],"keys_pem":[]`), `config_trust of type "registries"`},
		{"bytes on a config reference", withConfigTrust(`"type":"embedded_config_reference","bytes":"eA=="`), `config_trust of type "embedded_config_reference"`},
		{"unknown runtime reference member", withConfigTrust(`"type":"embedded_config_reference","runtime":{"extra":1}`), `config_trust of type "embedded_config_reference"`},
		{"artifacts not an object", `{"policy":{"artifacts":"embedded"}}`, "parsing artifacts"},
		{"artifacts without a type", withArtifacts(`"freshness_keys_pem":[]`), "artifacts requires a type"},
		{"unknown artifacts type", withArtifacts(`"type":"pinned"`), `unknown type "pinned"`},
		{"member of another artifacts type", withArtifacts(`"type":"endorsed","runtime":"eA=="`), `artifacts of type "endorsed"`},
		{"config trust in the policy", `{"policy":{"config_trust":{"type":"registries"}}}`, "parsing verification options"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(tc.options)
			requireUsageError(t, err, tc.contains)
		})
	}
}
