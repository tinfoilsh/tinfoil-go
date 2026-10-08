package enclave

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestConfigHandlesRetainExplicitProfile(t *testing.T) {
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
	ref := "org/project@v1@sha256:" + strings.Repeat("ab", sha256.Size)
	keys := []crypto.PublicKey{key.Public()}
	host := strings.TrimPrefix(server.URL, "https://")
	const maxAge = time.Hour
	client, err := NewConfigHandle(host, ref, keys, &Options{FreshnessMaxAge: maxAge})
	require.NoError(t, err)
	public, err := NewConfigHandle(host, ref, nil, nil)
	require.NoError(t, err)
	_, err = public.fetchVerification()
	require.ErrorContains(t, err, collateral.ConfigID)
	_, err = NewConfigHandle(host, ref, []crypto.PublicKey{}, nil)
	require.ErrorContains(t, err, "must not be empty")
	for _, derived := range []*Handle{client, client.ForEnclave(host), client.ViaRelay(host)} {
		require.Equal(t, ref, derived.Repo())
		require.Equal(t, maxAge, derived.verifier.FreshnessMaxAge())
		_, err := derived.fetchVerification()
		require.ErrorContains(t, err, collateral.ConfigID)
	}
	for _, invalid := range []string{"/org/project", "Org/project", "org/project@../v1"} {
		_, err := NewConfigHandle(host, invalid, nil, nil)
		var configuration *ConfigurationError
		require.ErrorAs(t, err, &configuration)
	}
	legacy, err := NewHandle(host, ref, nil)
	require.NoError(t, err)
	_, err = legacy.fetchVerification()
	require.ErrorContains(t, err, collateral.SigstoreCodeV1Format)
	verified := &verify.Verification{Config: &verify.ConfigVerification{Name: "/org/project/v1"}}
	cloned := cloneVerification(verified)
	cloned.Config.Name = "changed"
	require.Equal(t, "/org/project/v1", verified.Config.Name)
}
