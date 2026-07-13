// Package tdx authenticates Intel TDX quotes against the pinned Intel SGX
// root, replaying the document's own captured PCS collateral, and assembles
// complete go-tdx-guest validation options from an endorsed policy.
package tdx

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

//go:generate sh -xc "curl -o sgx_root_ca.pem https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"

//go:embed sgx_root_ca.pem
var sgxRootCACertPEM []byte

var intelRootCertPool *x509.CertPool

func init() {
	root, _ := pem.Decode(sgxRootCACertPEM)
	cert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		panic("failed to parse Intel root certificate: " + err.Error())
	}
	intelRootCertPool = x509.NewCertPool()
	intelRootCertPool.AddCert(cert)
}
