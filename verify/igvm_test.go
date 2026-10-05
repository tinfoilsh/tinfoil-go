package verify

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
)

const (
	testIdentity = "/tinfoil/model-router"
	testScope    = "16a44d18-3387-44ce-9bfb-d77c4d27dbba"
)

func testPin() ConfigPin { return ConfigPin{Identity: testIdentity, AuditScope: testScope} }

func testSigningKey(t *testing.T) endorsement.SigningKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return endorsement.SigningKey{PublicKey: key.Public(), AuditScope: testScope}
}

func TestConfigPinValidate(t *testing.T) {
	require.NoError(t, testPin().Validate())
	for _, tt := range []struct {
		name string
		pin  ConfigPin
	}{
		{"no identity", ConfigPin{AuditScope: testScope}},
		{"bad identity", ConfigPin{Identity: "tinfoil/model-router", AuditScope: testScope}},
		{"no scope", ConfigPin{Identity: testIdentity}},
		{"bad scope", ConfigPin{Identity: testIdentity, AuditScope: "not-a-uuid"}},
		{"bad revision", ConfigPin{Identity: testIdentity, AuditScope: testScope, Revision: "bad/revision"}},
		{"short digest", ConfigPin{Identity: testIdentity, AuditScope: testScope, Digest: "ab"}},
		{"upper digest", ConfigPin{Identity: testIdentity, AuditScope: testScope, Digest: strings.Repeat("AB", 32)}},
	} {
		t.Run(tt.name, func(t *testing.T) { require.Error(t, tt.pin.Validate()) })
	}
}

// A verifier told no registry keys says so as a configuration error, not a
// failed attestation.
func TestVerifyConfigRequiresSigningKeys(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	_, err = v.VerifyConfig(nil, make([]byte, document.NonceSize), testPin())
	var configErr *errs.ConfigurationError
	require.ErrorAs(t, err, &configErr)
	require.ErrorContains(t, err, "WithConfigSigningKeys")
}

// The approval is the only evidence a config has not been withdrawn.
func TestVerifyConfigRefusesIgnoredFreshness(t *testing.T) {
	v, err := NewVerifier(WithConfigSigningKeys([]endorsement.SigningKey{testSigningKey(t)}), WithIgnoreFreshness())
	require.NoError(t, err)
	_, err = v.VerifyConfig(nil, make([]byte, document.NonceSize), testPin())
	require.ErrorContains(t, err, "cannot ignore freshness")
}

func TestVerifyConfigRejectsBadPin(t *testing.T) {
	v, err := NewVerifier(WithConfigSigningKeys([]endorsement.SigningKey{testSigningKey(t)}))
	require.NoError(t, err)
	_, err = v.VerifyConfig(nil, make([]byte, document.NonceSize), ConfigPin{})
	var configErr *errs.ConfigurationError
	require.ErrorAs(t, err, &configErr)
}

func TestWithConfigSigningKeysRequiresKeys(t *testing.T) {
	_, err := NewVerifier(WithConfigSigningKeys(nil))
	require.ErrorContains(t, err, "at least one config signing key")
}

// A document carrying no config endorsement cannot be appraised by this flow.
func TestVerifyConfigRequiresConfigCollateral(t *testing.T) {
	v, err := NewVerifier(WithConfigSigningKeys([]endorsement.SigningKey{testSigningKey(t)}))
	require.NoError(t, err)
	docBytes, nonce := buildIGVMDocument(t, nil)
	_, err = v.VerifyConfig(docBytes, nonce, testPin())
	require.ErrorIs(t, err, collateral.ErrNotFound)
	require.ErrorContains(t, err, collateral.ConfigEndorsementV1Format)
}

// With a config endorsement present the flow reaches the registry approval,
// which an unsigned config cannot pass. That is as far as this can go without
// a real approval, which needs a real Sigstore timestamp and log entry.
func TestVerifyConfigReachesRegistryApproval(t *testing.T) {
	v, err := NewVerifier(WithConfigSigningKeys([]endorsement.SigningKey{testSigningKey(t)}))
	require.NoError(t, err)
	docBytes, nonce := buildIGVMDocument(t, []collateral.Entry{configEntry(t, igvmFixture(t, "config-placeholder.yaml"))})
	_, err = v.VerifyConfig(docBytes, nonce, testPin())
	require.ErrorContains(t, err, "verifying config approval")
}

// configEntry carries exact config bytes with a placeholder bundle; the
// collateral layer only requires one to be present.
func configEntry(t *testing.T, config []byte) collateral.Entry {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"config_base64":   base64.StdEncoding.EncodeToString(config),
		"sigstore_bundle": map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
	})
	require.NoError(t, err)
	return collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV1Format, Data: data}
}

// buildIGVMDocument produces a parseable v3 document with a stub quote.
func buildIGVMDocument(t *testing.T, entries []collateral.Entry) ([]byte, []byte) {
	t.Helper()
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	docBytes, err := document.Build(document.BuildInput{Nonce: nonce, Collateral: entries},
		func([64]byte) (string, []byte, error) {
			return document.SEVSNPReportV1Format, make([]byte, 1184), nil
		})
	require.NoError(t, err)
	return docBytes, nonce
}

// The one entry a collaterals service must add for this flow round-trips into
// the accessor it reads; everything else a repo request already carries.
func TestIGVMCollateralRoundTrip(t *testing.T) {
	config := igvmFixture(t, "config-placeholder.yaml")
	docBytes, nonce := buildIGVMDocument(t, []collateral.Entry{configEntry(t, config)})
	doc, err := document.Parse(docBytes, nonce)
	require.NoError(t, err)
	approval, err := doc.ConfigEndorsement()
	require.NoError(t, err)
	assert.Equal(t, config, approval.Config)
}

// The config flow witnesses the cvmimage release through the code entry, the
// same way the repo flow witnesses a workload release.
func TestRuntimeFreshnessIsTheCodeWitness(t *testing.T) {
	v, err := NewVerifier(WithConfigSigningKeys([]endorsement.SigningKey{testSigningKey(t)}))
	require.NoError(t, err)
	docBytes, nonce := buildIGVMDocument(t, []collateral.Entry{configEntry(t, igvmFixture(t, "config-placeholder.yaml"))})
	doc, err := document.Parse(docBytes, nonce)
	require.NoError(t, err)

	_, err = v.witness(doc, collateral.FreshnessIDCode, &provenance.AuthenticatedArtifact{}, time.Now(), "code")
	require.ErrorIs(t, err, collateral.ErrNotFound)
	require.ErrorContains(t, err, collateral.FreshnessIDCode)
}

// Validation keeps the pin to one repository, so it can narrow which release
// is acceptable but never redirect the runtime elsewhere.
func TestConfigPinRuntimeValidate(t *testing.T) {
	for _, runtime := range []string{
		"tinfoilsh/cvmimage",
		"tinfoilsh/cvmimage@v0.15.0-rc6",
		"tinfoilsh/cvmimage@sha256:" + strings.Repeat("ab", 32),
		"tinfoilsh/cvmimage@v0.15.0-rc6@sha256:" + strings.Repeat("ab", 32),
	} {
		pin := testPin()
		pin.Runtime = runtime
		require.NoError(t, pin.Validate(), runtime)
	}
	for _, tt := range []struct{ name, runtime, wantErr string }{
		{"another repository", "evil/cvmimage", "want \"tinfoilsh/cvmimage\""},
		{"a fork", "tinfoilsh/cvmimage-fork", "want \"tinfoilsh/cvmimage\""},
		{"not a reference", "not a repo", "invalid release reference"},
		{"no owner", "cvmimage", "invalid release reference"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pin := testPin()
			pin.Runtime = tt.runtime
			require.ErrorContains(t, pin.Validate(), tt.wantErr)
		})
	}
}

// The reference codeReferences is given is the one AuthenticateCode enforces,
// digest pin and all. The real platform-endorsements bundle stands in for a
// code artifact: unpinned it reaches its predicate being the wrong kind, and
// with a digest it does not carry it is refused before that.
func TestRuntimeReferenceReachesAuthenticateCode(t *testing.T) {
	v, err := NewVerifier(WithConfigSigningKeys([]endorsement.SigningKey{testSigningKey(t)}))
	require.NoError(t, err)
	bundle := igvmFixture(t, "platform-bundle.json")
	const platformRepo = "tinfoilsh/platform-endorsements"
	data, err := json.Marshal(map[string]any{
		"repo": platformRepo, "tag": realPlatformTag, "digest": realPlatformSHA,
		"sigstore_bundle": jsontext.Value(bundle),
	})
	require.NoError(t, err)
	docBytes, nonce := buildIGVMDocument(t, []collateral.Entry{{
		ID: "code", Role: collateral.RoleReferenceValues,
		Format: collateral.SigstoreCodeV1Format, Data: data,
	}})
	doc, err := document.Parse(docBytes, nonce)
	require.NoError(t, err)

	_, unpinned := v.codeReferences(doc, platformRepo, time.Now())
	require.ErrorContains(t, unpinned, "unsupported predicate type",
		"the document's own digest verified, so appraisal reached the predicate")

	_, pinned := v.codeReferences(doc, platformRepo+"@sha256:"+strings.Repeat("cd", 32), time.Now())
	require.ErrorContains(t, pinned, "verifying bundle",
		"the pinned digest replaced the document's and was refused first")
}

// An unset pin leaves the reference exactly the constant.
func TestConfigPinRuntimeDefaultsToTheConstant(t *testing.T) {
	assert.Empty(t, testPin().Runtime)
	assert.Equal(t, runtimeRepo, cmp.Or(testPin().Runtime, runtimeRepo))
	assert.Equal(t, "tinfoilsh/cvmimage", runtimeRepo)
}
