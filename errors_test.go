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
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	sdkerrors "github.com/tinfoilsh/tinfoil-go/verifier/errors"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/tdx"
)

func TestErrorContract(t *testing.T) {
	cause := &url.Error{Op: "Get", URL: "https://enclave.example", Err: context.DeadlineExceeded}
	for _, tc := range []struct {
		prefix string
		wrap   func(error) error
		target any
	}{
		{"configuration", sdkerrors.Configuration, new(*tinfoil.ConfigurationError)},
		{"fetch", sdkerrors.Fetch, new(*tinfoil.FetchError)},
		{"attestation", sdkerrors.Attestation, new(*tinfoil.AttestationError)},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			err := tc.wrap(cause)
			require.ErrorAs(t, err, tc.target)
			var sdkError tinfoil.Error
			require.ErrorAs(t, err, &sdkError)
			var networkError *url.Error
			require.ErrorAs(t, err, &networkError)
			require.Same(t, cause, networkError)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Equal(t, tc.prefix+" error: "+cause.Error(), err.Error(), "gomobile prefix contract")
			for _, wrap := range []func(error) error{sdkerrors.Configuration, sdkerrors.Fetch, sdkerrors.Attestation} {
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
	var absent *client.SecureClient
	_, err = absent.Verify()
	require.ErrorAs(t, err, &config)
	s, err := client.NewSecureClient("enclave.example", "org/repo", nil)
	require.NoError(t, err)
	_, err = s.Request("GET", "://", "", nil)
	require.ErrorAs(t, err, &config)
	_, err = envelope.Fetch("", make([]byte, envelope.NonceSize))
	require.ErrorAs(t, err, &config)
	_, err = quote.Authenticate(nil)
	require.ErrorAs(t, err, &config)
	_, err = quote.Assemble(nil, nil, nil, nil, [64]byte{}, nil)
	require.ErrorAs(t, err, &config)
	_, err = quote.Assemble(&policy.Artifact{}, nil, nil, nil, [64]byte{}, &quote.Authenticated{})
	require.ErrorAs(t, err, &config)
	_, err = sev.Assemble(&policy.SEVSNPPolicy{}, &sev.Quote{}, "", [64]byte{})
	require.ErrorAs(t, err, &config)
	_, _, err = tdx.Assemble(&policy.Artifact{}, &policy.TDXPolicy{}, &policy.Shape{}, &tdx.Quote{}, [5]string{}, [64]byte{})
	require.ErrorAs(t, err, &config)
	for _, assembled := range []*quote.AssembledPolicy{nil, {}} {
		require.ErrorAs(t, assembled.Validate(), &config)
	}
	for _, expected := range []*sev.Expectations{nil, {}} {
		require.ErrorAs(t, expected.Validate(nil), &config)
	}
	for _, expected := range []*tdx.Expectations{nil, {}} {
		require.ErrorAs(t, expected.Validate(nil), &config)
	}
	var verified *client.VerifiedDocumentV3
	_, err = verified.TLSPublicKeyFP()
	require.ErrorAs(t, err, &config)

	var attestation *tinfoil.AttestationError
	_, err = client.VerifyDocumentV3([]byte(`{}`), make([]byte, envelope.NonceSize), "org/repo", nil)
	require.ErrorAs(t, err, &attestation, "malformed evidence is not a caller configuration error")
}
