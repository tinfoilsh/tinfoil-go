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
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
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
		{"network", errs.WrapNetwork(cause), new(*tinfoil.NetworkError)},
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
			for _, wrap := range []func(error) error{errs.WrapNetwork, errs.WrapAttestation} {
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
	_, err := tinfoil.NewEnclaveHTTPClient("enclave.example", "org/repo", &tinfoil.EnclaveOptions{TransportMode: "invalid"})
	require.ErrorAs(t, err, &config)
	var usage *verify.UsageError
	verifier, err := verify.NewVerifier()
	require.NoError(t, err)
	_, err = verifier.VerifyV3(nil, nil, "")
	require.ErrorAs(t, err, &usage)
	_, err = verifier.VerifyV3(nil, nil, "org/repo")
	require.ErrorAs(t, err, &usage)
	_, err = tinfoil.NewEnclaveHTTPClient("", "", nil)
	require.ErrorAs(t, err, &config, "reject a missing enclave before fetching")
	for _, repo := range []string{"owner", "owner/repo/extra", "owner/repo@sha256:bad"} {
		_, err = tinfoil.NewEnclaveHTTPClient("enclave.example", repo, nil)
		require.ErrorAs(t, err, &config)
		_, err = verifier.VerifyV3(nil, nil, repo)
		require.ErrorAs(t, err, &usage)
	}
	_, err = enclave.NewHandle(enclave.Config{Host: "enclave.example", Repo: "org/repo@v1@sha256:" + strings.Repeat("a", 64)})
	require.NoError(t, err)
	_, err = fetch.Document(t.Context(), "", "", make([]byte, document.NonceSize))
	require.ErrorAs(t, err, &config)
	var verified *verify.Verification
	_, ok := verified.TLSPublicKeyFP()
	require.False(t, ok, "a nil verification endorses nothing")

	var rejected *verify.VerificationError
	_, err = verifier.VerifyV3([]byte(`{}`), make([]byte, document.NonceSize), "org/repo")
	require.ErrorAs(t, err, &rejected, "malformed evidence is not a usage error")
}

func TestMalformedPinsAreRejectedBeforeAnyClient(t *testing.T) {
	// Registers are parsed when pins are built, so a pointer is the only
	// malformed pin the API can express.
	register := measurement.Register{0xab}
	for _, pins := range []measurement.Expected{
		(*measurement.ExpectedSEVSNP)(nil),
		(*measurement.ExpectedTDX)(nil),
		&measurement.ExpectedTDX{RTMR3: &register},
	} {
		_, err := verify.NewVerifier(verify.WithPinnedRegisters(pins))
		var usage *verify.UsageError
		require.ErrorAs(t, err, &usage)
	}
	for _, pins := range []measurement.Expected{
		measurement.ExpectedSEVSNP{Launch: &register},
		measurement.ExpectedTDX{RTMR3: &register},
	} {
		_, err := verify.NewVerifier(verify.WithPinnedRegisters(pins))
		require.NoError(t, err, "sparse pins remain supported")
	}
}
