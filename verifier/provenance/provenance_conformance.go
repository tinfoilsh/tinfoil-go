//go:build tinfoil_conformance

package provenance

import "github.com/tinfoilsh/tinfoil-go/verifier/policy"

func AuthenticateCodeWithRoot(bundleJSON []byte, repo, hexDigest string, trustRootJSON []byte) (*Code, error) {
	return authenticateCodeWithRoot(bundleJSON, repo, hexDigest, trustRootJSON)
}

func AuthenticateEndorsementsWithRoot(bundleJSON []byte, hexDigest string, trustRootJSON []byte) (*policy.Artifact, error) {
	return authenticateEndorsementsWithRoot(bundleJSON, hexDigest, trustRootJSON)
}
