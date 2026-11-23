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
		{"invalid options", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"policy":{"freshness_max_age_ns":-1}}`); return err }},
		{"unknown option", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"enclave":"x"}`); return err }},
		{"misspelled option", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"policy":{"freshness_max_age":1}}`); return err }},
		{"options not an object", UsageErrorPrefix, func() error { _, err := NewVerifier(`null`); return err }},
		{"malformed trust option", UsageErrorPrefix, func() error { _, err := NewVerifier(`{"config_trust":{"type":"embedded_config"}}`); return err }},
		{"URL as host", UsageErrorPrefix, func() error { _, err := AttestationURL("https://enclave.example", "", nonce); return err }},
		{"invalid repo", UsageErrorPrefix, func() error { _, err := verifier.Verify(doc, nonce, "owner", ""); return err }},
		{"short nonce", UsageErrorPrefix, func() error { _, err := verifier.Verify([]byte("{}"), nonce[1:], routerRepo, ""); return err }},
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
	verifier, err := NewVerifier(`{"policy":{"freshness_max_age_ns":3600000000000,` +
		`"pinned_registers":{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["","","","","` + register + `"]}}}`)
	require.NoError(t, err)
	assert.Equal(t, time.Hour, verifier.inner.FreshnessMaxAge())
	rtmr3, err := measurement.ParseRegister(register)
	require.NoError(t, err)
	assert.Equal(t, measurement.ExpectedTDX{RTMR3: &rtmr3}, verifier.inner.PinnedRegisters())

	defaults, err := NewVerifier("")
	require.NoError(t, err)
	assert.Equal(t, 7*24*time.Hour, defaults.inner.FreshnessMaxAge())
	assert.Nil(t, defaults.inner.PinnedRegisters())
}

func TestNewVerifierRejectsMalformedPins(t *testing.T) {
	register := strings.Repeat("ab", 48)
	for name, pins := range map[string]string{
		"unknown type": `{"type":"https://tinfoil.sh/predicate/nope/v1","registers":[""]}`,
		"wrong count":  `{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["` + register + `"]}`,
		"not hex":      `{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":["zz"]}`,
		"wrong length": `{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":["abcd"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewVerifier(`{"policy":{"pinned_registers":` + pins + `}}`)
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), UsageErrorPrefix), err.Error())
		})
	}
}

// A verification that cannot authorize a request is reported as a failure, so
// a caller that re-verifies at FreshnessExpiresAt cannot loop on it.
func TestCheckFreshRejectsExpired(t *testing.T) {
	verified := sampleVerification()
	require.NoError(t, checkFresh(verified, verified.FreshnessExpiresAt().Add(-time.Second)))
	err := checkFresh(verified, verified.FreshnessExpiresAt())
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
	payload, err := verifier.Verify(doc, nonce, routerRepo, routerRepo)
	require.NoError(t, err)

	var got resultJSON
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	require.Nil(t, got.Error)
	require.NotNil(t, got.Report.VerifiedFacts)
	assert.Equal(t, routerRepo, got.Report.VerifiedFacts.ConfigRepo)
	assert.NotEmpty(t, got.Report.VerifiedFacts.HPKEPublicKey)

	_, err = verifier.Verify(doc, nonce[:len(nonce)-1], routerRepo, "")
	require.Error(t, err, "a nonce of the wrong size is a usage error")
	payload, err = verifier.Verify(doc, NewNonce(), routerRepo, "")
	require.NoError(t, err, "a rejection is a result")
	got = resultJSON{}
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	require.NotNil(t, got.Error, "a document verifies only against the nonce it was fetched with")
	assert.Equal(t, "envelope", got.Error.Layer)
}

// A rejected document is a result that carries the report, not an error.
func TestVerifyReturnsARejectionAsAResult(t *testing.T) {
	verifier, err := NewVerifier("")
	require.NoError(t, err)
	nonce := NewNonce()
	payload, err := verifier.Verify([]byte("{}"), nonce, routerRepo, "")
	require.NoError(t, err)
	var got resultJSON
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	require.NotNil(t, got.Error)
	assert.Equal(t, "envelope", got.Error.Layer)
	assert.True(t, strings.HasPrefix(got.Error.Message, VerificationErrorPrefix+"envelope: "), got.Error.Message)
	assert.Equal(t, VerificationSchemaVersion, got.SchemaVersion)
	require.Len(t, got.Report.Steps, 4)
	assert.Equal(t, "envelope", got.Report.Steps[0].Layer)
	assert.Equal(t, "failed", got.Report.Steps[0].Status)
	assert.NotEmpty(t, got.Report.Steps[0].Message)
	assert.False(t, strings.HasPrefix(got.Report.Steps[0].Message, VerificationErrorPrefix), "a step's message carries no prefix")
	assert.True(t, strings.HasSuffix(got.Error.Message, got.Report.Steps[0].Message), "the error's message is the step's, with the prefix")
	assert.Nil(t, got.Report.VerifiedFacts)
	require.NotNil(t, got.Report.PartialFacts)
	assert.Nil(t, got.Report.PartialFacts.Expected)
	assert.Nil(t, got.Report.PartialFacts.Measured)
}
