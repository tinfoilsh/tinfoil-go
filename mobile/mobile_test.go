package mobile

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

const routerRepo = "tinfoilsh/confidential-model-router"

// Swift tells error types apart by prefix alone, so toMobileError must lead
// each type's message with its exported prefix, and a verification error's
// with its layer, exactly once, while Go callers can still unwrap the type.
func TestErrorPrefixesMatchCategories(t *testing.T) {
	cause := errors.New("cause")
	for _, tc := range []struct {
		prefix   string
		category error
	}{
		{UsageErrorPrefix, &verify.UsageError{Err: cause}},
		{VerificationErrorPrefix + "quote: ", &verify.VerificationError{Layer: verify.LayerQuote, Err: cause}},
	} {
		prefix, category := tc.prefix, tc.category
		assert.Equal(t, prefix+"cause", toMobileError(category).Error())
		wrapped := toMobileError(fmt.Errorf("context: %w", category))
		assert.Equal(t, prefix+"context: cause", wrapped.Error())
		assert.ErrorIs(t, wrapped, category)
	}
	nested := toMobileError(&verify.VerificationError{Layer: verify.LayerProvenance, Err: &verify.UsageError{Err: cause}})
	assert.True(t, strings.HasPrefix(nested.Error(), VerificationErrorPrefix+"provenance: "), "the outermost verify error decides the prefix")
	assert.NoError(t, toMobileError(nil))
	uncategorized := errors.New("uncategorized")
	assert.Same(t, uncategorized, toMobileError(uncategorized))
}

// Every error crossing the FFI reaches Swift as text, so each must lead with
// the category Swift maps it to.
func TestErrorsLeadWithCategory(t *testing.T) {
	nonce := NewNonce()
	verifier, err := NewVerifier("")
	require.NoError(t, err)
	doc, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	require.NoError(t, err)
	for _, tt := range []struct {
		name   string
		prefix string
		call   func() error
	}{
		{"invalid options", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"freshness_max_age_ns":-1}`); return err }},
		{"unknown option", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"enclave":"x"}`); return err }},
		{"misspelled option", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"freshness_max_age":1}`); return err }},
		{"options not an object", UsageErrorPrefix, func() error { _, err := NewVerifier(`null`); return err }},
		{"option mobile cannot apply", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"embedded_config":{}}`); return err }},
		{"URL as host", UsageErrorPrefix, func() error { _, err := AttestationURL("https://enclave.example", "", nonce); return err }},
		{"invalid repo", UsageErrorPrefix, func() error { _, err := verifier.Verify(doc, nonce, "owner"); return err }},
		{"short nonce", UsageErrorPrefix, func() error { _, err := verifier.Verify([]byte("{}"), nonce[1:], routerRepo); return err }},
		{"malformed document", VerificationErrorPrefix + "envelope: ", func() error { _, err := verifier.Verify([]byte("{}"), nonce, routerRepo); return err }},
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
		`"pinned_registers":{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["","","","","` + register + `"]}}`)
	require.NoError(t, err)
	assert.Equal(t, time.Hour, verifier.inner.FreshnessMaxAge())
	assert.Equal(t, &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}, verifier.inner.PinnedRegisters())

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
	assert.True(t, strings.HasPrefix(toMobileError(err).Error(), VerificationErrorPrefix+"provenance: "), err.Error())
}

// The flow a mobile caller runs: its own fetch, then a stateless verify.
func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t)
	nonce := NewNonce()
	url, err := AttestationURL("inference.tinfoil.sh", "", nonce)
	require.NoError(t, err)
	doc, err := testutil.Get(url)
	require.NoError(t, err)
	verifier, err := NewVerifier("")
	require.NoError(t, err)
	payload, err := verifier.Verify(doc, nonce, routerRepo)
	require.NoError(t, err)

	var got verificationJSON
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	assert.Equal(t, routerRepo, got.ConfigRepo)
	assert.NotEmpty(t, got.HPKEPublicKey)

	_, err = verifier.Verify(doc, nonce[:len(nonce)-1], routerRepo)
	require.Error(t, err, "a document verifies only against the nonce it was fetched with")
	_, err = verifier.Verify(doc, NewNonce(), routerRepo)
	require.Error(t, err, "a document verifies only against the nonce it was fetched with")
}
