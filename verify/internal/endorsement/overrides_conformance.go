//go:build tinfoil_conformance

package endorsement

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// ErrDangerousTestOnlyInput marks an argument the conformance entry points
// below could not even use (a trust root that is not a trusted-root
// document, an empty key set, a PEM block that is not a public key, a key
// set with a repeated or unsupported key, a zero clock). The adapter reports
// those as MALFORMED_INPUT; every other error is a verification failure.
var ErrDangerousTestOnlyInput = errors.New("conformance input")

// DangerousTestOnlyVerifyApproval verifies a key-signed approval bundle the
// way FreshnessVerifier and ConfigVerifier do, with the signing keys and the
// trust root supplied by the conformance harness instead of pinned by the
// SDK. It only assembles the inputs; every rule comes from the verifier
// production runs. A nil trustRootJSON selects the embedded trusted root.
// It exists only in the conformance build because a caller-supplied key set
// destroys the guarantee that an approval came from Tinfoil.
func DangerousTestOnlyVerifyApproval(trustRootJSON []byte, keysPEM []string, bundleJSON []byte, digest []byte) (hint string, err error) {
	trust, err := dangerousTestOnlyTrustRoot(trustRootJSON)
	if err != nil {
		return "", err
	}
	if len(keysPEM) == 0 {
		return "", fmt.Errorf("%w: at least one signing key is required", ErrDangerousTestOnlyInput)
	}
	keys := make([]crypto.PublicKey, 0, len(keysPEM))
	for _, pem := range keysPEM {
		key, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pem))
		if err != nil {
			return "", fmt.Errorf("%w: parsing signing key: %w", ErrDangerousTestOnlyInput, err)
		}
		keys = append(keys, key)
	}
	// A trust root without transparency logs is a verification failure, like
	// every other shortfall of the root; once the logs are present, the only
	// way the verifier fails to assemble is a key set it cannot use.
	if len(trust.RekorLogs()) == 0 {
		return "", fmt.Errorf("Rekor trust is required")
	}
	verifier, err := newEndorsementVerifier(trust, keys)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDangerousTestOnlyInput, err)
	}
	b, err := parseEndorsementBundle(bundleJSON)
	if err != nil {
		return "", err
	}
	return verifier.Verify(b, digest)
}

// DangerousTestOnlyVerifyTimestamp verifies an RFC 3161 response over input
// against the trust root's timestamp authorities at the clock now, with the
// default approval age and skew, exactly as the inner approval timestamp is
// verified. A nil trustRootJSON selects the embedded trusted root. The
// timestamp verifier uses no signing keys, so the verifier is assembled from
// the trust root alone.
func DangerousTestOnlyVerifyTimestamp(trustRootJSON []byte, response, input []byte, now time.Time) (time.Time, error) {
	trust, err := dangerousTestOnlyTrustRoot(trustRootJSON)
	if err != nil {
		return time.Time{}, err
	}
	policy, err := newTimePolicy(now, 0, 0)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrDangerousTestOnlyInput, err)
	}
	verifier := &endorsementVerifier{trust: trust}
	return verifier.VerifyTimestamp(response, input, policy)
}

// dangerousTestOnlyTrustRoot parses the harness's trusted-root document, or
// returns the embedded one (the same bytes NewDefaultClient uses) for nil.
func dangerousTestOnlyTrustRoot(trustRootJSON []byte) (root.TrustedMaterial, error) {
	if trustRootJSON == nil {
		trustRootJSON = embeddedTrustedRoot
	}
	trust, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing trust root: %w", ErrDangerousTestOnlyInput, err)
	}
	return trust, nil
}
