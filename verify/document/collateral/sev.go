package collateral

import (
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/canonical"
)

// AMDVCEK is decoded amd-vcek collateral.
type AMDVCEK struct {
	VCEKDER []byte
	// CertChainPEM holds the ASK then ARK certificates.
	CertChainPEM string
}

// Clone returns a deep copy of v, or nil for a nil v.
func (v *AMDVCEK) Clone() *AMDVCEK {
	if v == nil {
		return nil
	}
	return &AMDVCEK{VCEKDER: slices.Clone(v.VCEKDER), CertChainPEM: v.CertChainPEM}
}

// AMDCRL is decoded amd-crl collateral.
type AMDCRL struct {
	CRLDER []byte
}

// Clone returns a deep copy of c, or nil for a nil c.
func (c *AMDCRL) Clone() *AMDCRL {
	if c == nil {
		return nil
	}
	return &AMDCRL{CRLDER: slices.Clone(c.CRLDER)}
}

// amdVCEKData is the data of an AMDVCEKV1Format entry.
type amdVCEKData struct {
	VCEKDERBase64 string `json:"vcek_der_base64"`
	CertChainPEM  string `json:"cert_chain_pem"`
}

// amdCRLData is the data of an AMDCRLV1Format entry.
type amdCRLData struct {
	CRLDERBase64 string `json:"crl_der_base64"`
}

func decodeAMDVCEK(entry *Entry) (*AMDVCEK, error) {
	var data amdVCEKData
	if err := unmarshalData(entry, "amd-vcek", &data); err != nil {
		return nil, err
	}
	der, err := canonical.DecodeBase64("vcek_der_base64", data.VCEKDERBase64)
	if err != nil {
		return nil, fmt.Errorf("amd-vcek collateral entry %q: %w", entry.ID, err)
	}
	return &AMDVCEK{VCEKDER: der, CertChainPEM: data.CertChainPEM}, nil
}

func decodeAMDCRL(entry *Entry) (*AMDCRL, error) {
	var data amdCRLData
	if err := unmarshalData(entry, "amd-crl", &data); err != nil {
		return nil, err
	}
	der, err := canonical.DecodeBase64("crl_der_base64", data.CRLDERBase64)
	if err != nil {
		return nil, fmt.Errorf("amd-crl collateral entry %q: %w", entry.ID, err)
	}
	return &AMDCRL{CRLDER: der}, nil
}
