package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func TestLiveVerificationRecordsRepoAndMetadata(t *testing.T) {
	const enclaveEnvVar, repoEnvVar = "TINFOIL_ENCLAVE", "TINFOIL_REPO"
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	repo := os.Getenv(repoEnvVar)
	configRepo, _, _, err := ParseReference(repo)
	require.NoError(t, err)
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := fetch.Document(t.Context(), os.Getenv(enclaveEnvVar), "", nonce)
	require.NoError(t, err)
	verifier, err := NewVerifier()
	require.NoError(t, err)

	before := time.Now()
	verified, err := verifier.VerifyV3(raw, nonce, repo)
	after := time.Now()
	require.NoError(t, err)
	require.Equal(t, configRepo, verified.ConfigRepo)
	require.Equal(t, SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()}, verified.Metadata.Verifier)
	require.Equal(t, time.UTC, verified.Metadata.VerifiedAt.Location())
	require.WithinRange(t, verified.Metadata.VerifiedAt, before, after)

	// A tag pin selects the release but is not part of the repository name.
	require.NotEmpty(t, verified.CodeTag)
	pinned, err := verifier.VerifyV3(raw, nonce, configRepo+"@"+verified.CodeTag)
	require.NoError(t, err)
	require.Equal(t, configRepo, pinned.ConfigRepo)
}

// VerifyV3 reads its clock once and the CPU evidence layer appraises vendor
// collateral at that same instant. The AMD CRL window is checked before any
// signature, so a CRL valid only at a frozen instant shows which clock the
// quote layer used.
func TestVerifyAppraisesCPUEvidenceAtTheVerificationInstant(t *testing.T) {
	appraisal := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "test CRL issuer"}, KeyUsage: x509.KeyUsageCRLSign, SubjectKeyId: []byte{1}}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: appraisal.Add(-time.Hour), NextUpdate: appraisal.Add(time.Hour),
	}, issuer, key)
	require.NoError(t, err)
	chain, err := os.ReadFile(filepath.Join("internal", "quote", "sev", "turin_cert_chain.pem"))
	require.NoError(t, err)
	vcek, err := json.Marshal(map[string]string{"vcek_der_base64": base64.StdEncoding.EncodeToString([]byte("vcek")), "cert_chain_pem": string(chain)})
	require.NoError(t, err)
	crlData, err := json.Marshal(map[string]string{"crl_der_base64": base64.StdEncoding.EncodeToString(crl)})
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3,
		collateral.Entry{ID: "vcek", Role: collateral.RoleEndorsement, Format: collateral.AMDVCEKV1Format, Subjects: []string{collateral.SubjectCPU}, Data: vcek},
		collateral.Entry{ID: "crl", Role: collateral.RoleEndorsement, Format: collateral.AMDCRLV1Format, Subjects: []string{collateral.SubjectCPU}, Data: crlData},
	)

	v, err := NewVerifier(WithEmbeddedReferences(embeddedInputs(t)))
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, "")
	requireRejectedAt(t, err, LayerQuote)
	require.ErrorContains(t, err, "outside its validity window")

	_, err = v.VerifyV3At(raw, nonce, "", appraisal)
	requireRejectedAt(t, err, LayerQuote)
	require.ErrorContains(t, err, "must be exactly", "the CRL window passed at the caller's instant")
}

func TestVerifyV3AtRequiresAnInstant(t *testing.T) {
	v, err := NewVerifier(WithEmbeddedReferences(embeddedInputs(t)))
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	_, err = v.VerifyV3At(raw, nonce, "", time.Time{})
	require.ErrorAs(t, err, new(*UsageError))
	require.ErrorContains(t, err, "verification time must not be zero")

	var unbuilt *Verifier
	_, err = unbuilt.VerifyV3(raw, nonce, "")
	require.ErrorAs(t, err, new(*UsageError))
	require.ErrorContains(t, err, "verifier must be built with NewVerifier")
}
