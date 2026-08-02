//go:build tinfoil_conformance

package tdx

import "github.com/tinfoilsh/tinfoil-go/verifier/envelope"

func AuthenticateWithRoot(doc *envelope.Document, intelSGXRootPEM []byte) (*Quote, error) {
	return authenticateWithRoot(doc, intelSGXRootPEM)
}
