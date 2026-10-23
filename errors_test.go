package tinfoil_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestErrorContract(t *testing.T) {
	cause := &url.Error{Op: "Get", URL: "https://enclave.example", Err: context.DeadlineExceeded}
	for _, tc := range []struct {
		prefix string
		err    error
		target any
	}{
		{"configuration", &tinfoil.ConfigurationError{Err: cause}, new(*tinfoil.ConfigurationError)},
		{"fetch", errs.WrapFetch(cause), new(*tinfoil.FetchError)},
		{"attestation", errs.WrapAttestation(cause), new(*tinfoil.AttestationError)},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			err := tc.err
			require.ErrorAs(t, err, tc.target)
			var sdkError tinfoil.Error
			require.ErrorAs(t, err, &sdkError)
			var networkError *url.Error
			require.ErrorAs(t, err, &networkError)
			require.Same(t, cause, networkError)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Equal(t, tc.prefix+" error: "+cause.Error(), err.Error(), "gomobile prefix contract")
			for _, wrap := range []func(error) error{errs.WrapFetch, errs.WrapAttestation} {
				require.Nil(t, wrap(nil))
				for _, classified := range []error{err, fmt.Errorf("context: %w", err), errors.Join(err, context.Canceled)} {
					require.Same(t, classified, wrap(classified), "do not reclassify or double-wrap SDK errors")
				}
			}
		})
	}
}

func TestPublicInputErrors(t *testing.T) {
	var config *tinfoil.ConfigurationError
	_, err := tinfoil.NewClientWithOptions(tinfoil.WithTransport("invalid"))
	require.ErrorAs(t, err, &config)
	var usage *verify.UsageError
	verifier, err := verify.NewVerifier()
	require.NoError(t, err)
	_, err = verifier.VerifyV3(nil, nil, "")
	require.ErrorAs(t, err, &usage)
	_, err = verifier.VerifyV3(nil, nil, "org/repo")
	require.ErrorAs(t, err, &usage)
	_, err = enclave.NewHandle("enclave.example", "", nil)
	require.ErrorAs(t, err, &config, "reject missing trust configuration before fetching")
	for _, repo := range []string{"owner", "owner/repo/extra", "owner/repo@sha256:bad"} {
		_, err = enclave.NewHandle("enclave.example", repo, nil)
		require.ErrorAs(t, err, &config)
		_, err = verifier.VerifyV3(nil, nil, repo)
		require.ErrorAs(t, err, &usage)
	}
	_, err = enclave.NewHandle("enclave.example", "org/repo@v1@sha256:"+strings.Repeat("a", 64), nil)
	require.NoError(t, err)
	s, err := enclave.NewHandle("enclave.example", "org/repo", nil)
	require.NoError(t, err)
	_, err = s.Request("GET", "://", "", nil)
	require.ErrorAs(t, err, &config)
	_, err = fetch.Document(t.Context(), "", "", make([]byte, document.NonceSize))
	require.ErrorAs(t, err, &config)
	var verified *verify.Verification
	_, ok := verified.TLSPublicKeyFP()
	require.False(t, ok, "a nil verification endorses nothing")

	var rejected *verify.VerificationError
	_, err = verifier.VerifyV3([]byte(`{}`), make([]byte, document.NonceSize), "org/repo")
	require.ErrorAs(t, err, &rejected, "malformed evidence is not a usage error")
}

func TestMalformedPinsAreConfigurationErrors(t *testing.T) {
	// Registers are parsed when pins are built, so a nil pointer is the only
	// malformed pin the API can express.
	for _, pins := range []measurement.Expected{(*measurement.ExpectedSEVSNP)(nil), (*measurement.ExpectedTDX)(nil)} {
		opts := &enclave.Options{PinnedRegisters: pins}
		_, err := enclave.NewHandle("enclave.example", "org/repo", opts)
		var config *tinfoil.ConfigurationError
		require.ErrorAs(t, err, &config)
		_, err = enclave.NewDefaultHandle(opts)
		require.ErrorAs(t, err, &config, "reject malformed pins before discovery")
		_, err = verify.NewVerifier(verify.WithPinnedRegisters(pins))
		var usage *verify.UsageError
		require.ErrorAs(t, err, &usage)
	}
	register := measurement.Register{0xab}
	for _, pins := range []measurement.Expected{
		measurement.ExpectedSEVSNP{Launch: &register},
		measurement.ExpectedTDX{RTMR3: &register},
		&measurement.ExpectedTDX{RTMR3: &register},
	} {
		_, err := enclave.NewHandle("enclave.example", "org/repo", &enclave.Options{PinnedRegisters: pins})
		require.NoError(t, err, "sparse and pointer pins remain supported")
	}
}
