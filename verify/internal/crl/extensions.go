// Package crl checks the extension semantics supported by quote verification.
package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var (
	deltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	issuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	certificateIssuer        = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// CheckExtensions restricts verification to complete, direct CRLs. The quote
// libraries do not combine delta CRLs or process distribution-point scopes.
func CheckExtensions(list *x509.RevocationList) error {
	if err := checkExtensions(list.Extensions); err != nil {
		return err
	}
	for _, entry := range list.RevokedCertificateEntries {
		if err := checkExtensions(entry.Extensions); err != nil {
			return err
		}
	}
	return nil
}

func checkExtensions(extensions []pkix.Extension) error {
	for _, extension := range extensions {
		if extension.Critical || extension.Id.Equal(deltaCRLIndicator) ||
			extension.Id.Equal(issuingDistributionPoint) || extension.Id.Equal(certificateIssuer) {
			return fmt.Errorf("unsupported CRL extension %s", extension.Id)
		}
	}
	return nil
}
