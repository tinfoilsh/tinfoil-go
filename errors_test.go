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
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/client"
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
		{"fetch", verify.WrapFetch(cause), new(*tinfoil.FetchError)},
		{"attestation", verify.WrapAttestation(cause), new(*tinfoil.AttestationError)},
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
			for _, wrap := range []func(error) error{verify.WrapFetch, verify.WrapAttestation} {
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
	_, err = client.VerifyDocumentV3(nil, nil, "", nil)
	require.ErrorAs(t, err, &config)
	_, err = client.VerifyDocumentV3(nil, nil, "org/repo", nil)
	require.ErrorAs(t, err, &config)
	_, err = client.NewSecureClient("enclave.example", "", nil)
	require.ErrorAs(t, err, &config, "reject missing trust configuration before fetching")
	for _, repo := range []string{"owner", "owner/repo/extra", "owner/repo@sha256:bad"} {
		_, err = client.NewSecureClient("enclave.example", repo, nil)
		require.ErrorAs(t, err, &config)
		_, err = client.VerifyDocumentV3(nil, nil, repo, nil)
		require.ErrorAs(t, err, &config)
	}
	_, err = client.NewSecureClient("enclave.example", "org/repo@v1@sha256:"+strings.Repeat("a", 64), nil)
	require.NoError(t, err)
	s, err := client.NewSecureClient("enclave.example", "org/repo", nil)
	require.NoError(t, err)
	_, err = s.Request("GET", "://", "", nil)
	require.ErrorAs(t, err, &config)
	_, err = document.Fetch("", make([]byte, document.NonceSize))
	require.ErrorAs(t, err, &config)
	var verified *client.VerifiedDocumentV3
	_, err = verified.TLSPublicKeyFP()
	require.ErrorAs(t, err, &config)

	var attestation *tinfoil.AttestationError
	_, err = client.VerifyDocumentV3([]byte(`{}`), make([]byte, document.NonceSize), "org/repo", nil)
	require.ErrorAs(t, err, &attestation, "malformed evidence is not a caller configuration error")
}

func TestMalformedPinsAreConfigurationErrors(t *testing.T) {
	for _, pins := range []*measurement.Measurement{
		{Type: "unknown"},
		{Type: measurement.SevGuestV2},
		{Type: measurement.TdxGuestV2, Registers: []string{""}},
		{Type: measurement.SevGuestV2, Registers: []string{"bad"}},
		{Type: measurement.TdxGuestV2, Registers: []string{4: strings.Repeat("zz", 48)}},
	} {
		opts := &client.VerificationOptions{PinnedRegisters: pins}
		_, err := client.NewSecureClient("enclave.example", "org/repo", opts)
		var config *tinfoil.ConfigurationError
		require.ErrorAs(t, err, &config)
		_, err = client.NewDefaultClient(opts)
		require.ErrorAs(t, err, &config, "reject malformed pins before discovery")
		_, err = client.VerifyDocumentV3(nil, nil, "org/repo", opts)
		require.ErrorAs(t, err, &config)
	}
	for _, pins := range []*measurement.Measurement{
		{Type: measurement.SevGuestV2, Registers: []string{strings.Repeat("AB", 48)}},
		{Type: measurement.TdxGuestV2, Registers: []string{4: ""}},
	} {
		_, err := client.NewSecureClient("enclave.example", "org/repo", &client.VerificationOptions{PinnedRegisters: pins})
		require.NoError(t, err, "valid uppercase and sparse pins remain supported")
	}
}
