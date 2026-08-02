//go:build tinfoil_conformance

package client

import (
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

func VerifyDocumentV3WithAnchors(docBytes, nonce []byte, repo string, anchors quote.Anchors) (*VerifiedDocumentV3, error) {
	root := anchors.SigstoreTrustedRootJSON
	return verifyDocumentV3(docBytes, nonce,
		func(bundleJSON []byte, hexDigest string) (*provenance.Code, error) {
			return provenance.AuthenticateCodeWithRoot(bundleJSON, repo, hexDigest, root)
		},
		func(bundleJSON []byte, hexDigest string) (*policy.Artifact, error) {
			return provenance.AuthenticateEndorsementsWithRoot(bundleJSON, hexDigest, root)
		},
		func(doc *envelope.Document, e *policy.Artifact, m *measurement.Measurement, s *policy.Shape, rd [64]byte) (*quote.AssembledPolicy, *quote.Authenticated, error) {
			return quote.VerifyWithAnchors(doc, e, m, s, rd, anchors)
		},
	)
}
