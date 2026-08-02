//go:build tinfoil_conformance

package quote

import (
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/tdx"
)

// Anchors are injectable verification trust roots; a nil field uses the
// embedded pinned root.
type Anchors struct {
	// AMDRootCAPEM is the SEV-SNP ASK+ARK chain (KDS cert_chain PEM).
	AMDRootCAPEM []byte
	// IntelSGXRootPEM is the TDX Intel SGX root CA (PEM).
	IntelSGXRootPEM []byte
	// SigstoreTrustedRootJSON is the Sigstore trusted-root document (JSON).
	SigstoreTrustedRootJSON []byte
}

func AuthenticateWithAnchors(doc *envelope.Document, anchors Anchors) (*Authenticated, error) {
	return authenticate(doc,
		func(d *envelope.Document) (*sev.Quote, error) {
			return sev.AuthenticateWithRoot(d, anchors.AMDRootCAPEM)
		},
		func(d *envelope.Document) (*tdx.Quote, error) {
			return tdx.AuthenticateWithRoot(d, anchors.IntelSGXRootPEM)
		},
	)
}

func VerifyWithAnchors(doc *envelope.Document, endorsements *policy.Artifact, code *measurement.Measurement, shape *policy.Shape, reportData [64]byte, anchors Anchors) (*AssembledPolicy, *Authenticated, error) {
	return verify(doc, endorsements, code, shape, reportData,
		func(d *envelope.Document) (*Authenticated, error) { return AuthenticateWithAnchors(d, anchors) },
	)
}
