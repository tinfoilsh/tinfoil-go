//go:build tinfoil_conformance

package sev

import "github.com/tinfoilsh/tinfoil-go/verifier/envelope"

func AuthenticateWithRoot(doc *envelope.Document, amdRootCAPEM []byte) (*Quote, error) {
	return authenticateWithRoot(doc, amdRootCAPEM)
}
