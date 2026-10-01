package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func TestIGVMRequiresIndependentTrustAndFreshness(t *testing.T) {
	policy := ConfigPolicy{Identity: "/org/project", AuditScope: "16a44d18-3387-44ce-9bfb-d77c4d27dbba"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keys := []endorsement.SigningKey{{PublicKey: key.Public(), AuditScope: policy.AuditScope}}
	v, err := New()
	require.NoError(t, err)
	_, err = v.VerifyIGVM(nil, nil, policy)
	require.ErrorContains(t, err, "pinned signing keys")
	_, err = New(WithConfigSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	v, err = New(WithConfigSigningKeys(keys), WithIgnoreFreshness())
	require.NoError(t, err)
	_, err = v.VerifyIGVM(nil, nil, policy)
	require.ErrorContains(t, err, "requires config and platform freshness")

	v, err = New(WithConfigSigningKeys(keys))
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyIGVM(raw, nonce, policy)
	require.ErrorContains(t, err, document.ConfigCollateralID)
	for name, bad := range map[string]ConfigPolicy{
		"identity": {Identity: "/org/project/extra", AuditScope: policy.AuditScope},
		"scope":    {Identity: policy.Identity, AuditScope: "untrusted"},
		"revision": {Identity: policy.Identity, AuditScope: policy.AuditScope, Revision: "../v1"},
		"digest":   {Identity: policy.Identity, AuditScope: policy.AuditScope, Digest: strings.Repeat("AB", 32)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyIGVM(raw, nonce, bad)
			var e *ConfigurationError
			require.ErrorAs(t, err, &e)
		})
	}
}
