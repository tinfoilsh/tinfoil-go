package attestation

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

//go:generate sh -xc "curl -o sgx_root_ca.pem https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"

//go:embed sgx_root_ca.pem
var sgxRootCACertPEM []byte

// MinimumTcbEvaluationDataNumber is the minimum TCB evaluation data number
// required for collateral. This prevents accepting collateral issued before
// critical security updates. See Intel's TCB Recovery best practices.
const MinimumTcbEvaluationDataNumber = 19

// IntelQeVendorID is Intel's QE Vendor ID (939a7233-f79c-4ca9-940a-0db3957f0607)
var IntelQeVendorID = []byte{
	0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9,
	0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
}

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

// TDXGetterOption configures a TDXGetter.
