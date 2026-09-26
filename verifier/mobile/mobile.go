// Package mobile is the SDK's gomobile surface: the one package bound into
// Tinfoil.xcframework.
//
// It exists so the Go API does not have to be FFI-shaped. gomobile silently
// drops anything it cannot represent — maps, slices other than []byte, struct
// values, and every type from an unbound package, which includes time.Time and
// context.Context — so a package that is both a Go API and a binding target
// ends up serving neither well. Everything structured therefore crosses as
// JSON, and the shape of that JSON is declared in verification.go rather than
// inherited from whatever the SDK's types happen to look like.
package mobile

import (
	"encoding/json"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// Version is the Tinfoil SDK version.
const Version = client.Version

// Client verifies an enclave and reports what it proved. It wraps the SDK's
// own client, which is not itself bound.
type Client struct {
	inner *client.SecureClient
}

// NewClient verifies enclave against repo, a trusted
// owner/name[@tag][@sha256:digest] reference, using the default policy.
func NewClient(enclave, repo string) (result *Client, err error) {
	defer func() { err = mobileError(err) }()
	inner, err := client.NewSecureClient(enclave, repo, nil)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner}, nil
}

// NewClientWithOptions is NewClient with a policy, as the JSON object
// VerificationOptions describes: pinned registers and a freshness bound, the
// latter in integer nanoseconds. An empty string selects the default policy.
func NewClientWithOptions(enclave, repo, optionsJSON string) (result *Client, err error) {
	defer func() { err = mobileError(err) }()
	if optionsJSON == "" {
		return NewClient(enclave, repo)
	}
	opts, err := client.ParseVerificationOptionsJSON(optionsJSON)
	if err != nil {
		return nil, err
	}
	inner, err := client.NewSecureClient(enclave, repo, opts)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner}, nil
}

// Enclave returns the host this client verifies.
func (c *Client) Enclave() string { return c.inner.Enclave() }

// Repo returns the trusted repository reference, including any pins.
func (c *Client) Repo() string { return c.inner.Repo() }

// Verify re-verifies the enclave and returns what the document proved, as the
// JSON described in verification.go.
func (c *Client) Verify() (result string, err error) {
	defer func() { err = mobileError(err) }()
	verified, err := c.inner.Verify()
	if err != nil {
		return "", err
	}
	return encode(verified)
}

// Verification returns the last successful verification without re-verifying,
// or an empty string if this client has not verified yet.
func (c *Client) Verification() (result string, err error) {
	defer func() { err = mobileError(err) }()
	verified := c.inner.Verification()
	if verified == nil {
		return "", nil
	}
	return encode(verified)
}

func encode(verified *client.VerifiedDocumentV3) (string, error) {
	encoded, err := json.Marshal(toVerificationJSON(verified))
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
