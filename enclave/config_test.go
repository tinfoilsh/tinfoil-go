package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verifier"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/document/collateral"
)

func TestConfigClientsRetainExplicitProfile(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := hex.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err := document.Build(document.BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	original := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = original })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	policy := verifier.ConfigPolicy{Identity: "/org/project", AuditScope: "16a44d18-3387-44ce-9bfb-d77c4d27dbba"}
	keys := []endorsement.SigningKey{{PublicKey: key.Public(), AuditScope: policy.AuditScope}}
	host := strings.TrimPrefix(server.URL, "https://")
	client, err := NewConfigClient(host, policy, keys, nil)
	require.NoError(t, err)
	policy.Identity = "/other/project"
	for _, derived := range []*SecureClient{client, client.ForEnclave(host), client.ViaRelay(host)} {
		require.Equal(t, "/org/project", derived.configPolicy.Identity)
		_, err := derived.fetchVerification()
		require.ErrorContains(t, err, collateral.ConfigID)
	}
	legacy, err := NewSecureClient(host, "org/repo", nil)
	require.NoError(t, err)
	_, err = legacy.fetchVerification()
	require.ErrorContains(t, err, collateral.SigstoreCodeV1Format)
	verified := &VerifiedDocumentV3{Config: &endorsement.Verified{Name: "/org/project/v1"}}
	cloned := cloneVerification(verified)
	cloned.Config.Name = "changed"
	require.Equal(t, "/org/project/v1", verified.Config.Name)
}
