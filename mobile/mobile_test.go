package mobile

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

const (
	swiftOptions = `{"sdk":{"name":"tinfoil-swift","version":"0.8.2"}}`
	routerRepo   = "tinfoilsh/confidential-model-router"
)

// Swift tells error categories apart by prefix alone, so the exported prefixes
// must be the ones the SDK's error types produce.
func TestErrorPrefixesMatchCategories(t *testing.T) {
	cause := errors.New("cause")
	for prefix, err := range map[string]error{
		ConfigurationErrorPrefix: &verify.ConfigurationError{Err: cause},
		AttestationErrorPrefix:   &verify.AttestationError{Err: cause},
	} {
		assert.Equal(t, prefix+"cause", err.Error())
	}
}

// Every error crossing the FFI reaches Swift as text, so each must lead with
// the category Swift maps it to.
func TestErrorsLeadWithCategory(t *testing.T) {
	nonce := NewNonce()
	verifier, err := NewVerifier("")
	require.NoError(t, err)
	for _, tt := range []struct {
		name   string
		prefix string
		call   func() error
	}{
		{"invalid options", ConfigurationErrorPrefix, func() error { _, err := NewVerifier(`{"freshness_max_age_ns":-1}`); return err }},
		{"unknown option", ConfigurationErrorPrefix, func() error { _, err := NewVerifier(`{"enclave":"x"}`); return err }},
		{"URL as host", ConfigurationErrorPrefix, func() error { _, err := AttestationURL("https://enclave.example", "", nonce); return err }},
		{"invalid repo", ConfigurationErrorPrefix, func() error { _, err := verifier.Verify([]byte("{}"), nonce, "owner"); return err }},
		{"short nonce", ConfigurationErrorPrefix, func() error { _, err := verifier.Verify([]byte("{}"), nonce[1:], routerRepo); return err }},
		{"malformed document", AttestationErrorPrefix, func() error { _, err := verifier.Verify([]byte("{}"), nonce, routerRepo); return err }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), tt.prefix), err.Error())
		})
	}
}

func TestNewNonceIsFresh(t *testing.T) {
	first, second := NewNonce(), NewNonce()
	assert.Len(t, first, document.NonceSize)
	assert.False(t, bytes.Equal(first, second))
}

func TestNewVerifierAppliesOptions(t *testing.T) {
	register := strings.Repeat("ab", 48)
	verifier, err := NewVerifier(`{"freshness_max_age_ns":3600000000000,` +
		`"pinned_registers":{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["","","","","` + register + `"]},` +
		`"sdk":{"name":"tinfoil-swift","version":"0.8.2"}}`)
	require.NoError(t, err)
	assert.Equal(t, time.Hour, verifier.inner.FreshnessMaxAge())
	assert.Equal(t, &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}, verifier.inner.PinnedRegisters())
	assert.Equal(t, verify.SoftwareIdentity{Name: "tinfoil-swift", Version: "0.8.2"}, verifier.inner.Identity())

	defaults, err := NewVerifier("")
	require.NoError(t, err)
	assert.Equal(t, 7*24*time.Hour, defaults.inner.FreshnessMaxAge())
	assert.Nil(t, defaults.inner.PinnedRegisters())
}

// A verification that cannot authorize a request is reported as a failure, so
// a caller that re-verifies at FreshnessExpiresAt cannot loop on it.
func TestCheckFreshRejectsExpired(t *testing.T) {
	verified := sampleVerification()
	require.NoError(t, checkFresh(verified, verified.FreshnessExpiresAt.Add(-time.Second)))
	err := checkFresh(verified, verified.FreshnessExpiresAt)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), AttestationErrorPrefix), err.Error())
}

// The flow a mobile caller runs: its own fetch, then a stateless verify.
func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t)
	nonce := NewNonce()
	url, err := AttestationURL("inference.tinfoil.sh", "", nonce)
	require.NoError(t, err)
	doc, err := testutil.Get(url)
	require.NoError(t, err)
	verifier, err := NewVerifier(swiftOptions)
	require.NoError(t, err)
	payload, err := verifier.Verify(doc, nonce, routerRepo)
	require.NoError(t, err)

	var got verificationJSON
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	assert.Equal(t, routerRepo, got.ConfigRepo)
	assert.NotEmpty(t, got.HPKEPublicKey)
	assert.Equal(t, softwareIdentityJSON{Name: "tinfoil-swift", Version: "0.8.2"}, got.Verifier)

	_, err = verifier.Verify(doc, nonce[:len(nonce)-1], routerRepo)
	require.Error(t, err, "a document verifies only against the nonce it was fetched with")
	_, err = verifier.Verify(doc, NewNonce(), routerRepo)
	require.Error(t, err, "a document verifies only against the nonce it was fetched with")
}
