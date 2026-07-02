package policy

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"

	"github.com/google/go-tdx-guest/pcs"
)

// SEVIdentity returns the machines-map lookup key for a verified SEV-SNP
// report's CHIP_ID field. The field is always 64 bytes; Turin hardware
// delivers its 8-byte hwID zero-padded, which is exactly the endorsed form,
// so no product-specific handling is needed.
func SEVIdentity(chipID []byte) (string, error) {
	if len(chipID) != 64 {
		return "", fmt.Errorf("SEV CHIP_ID must be 64 bytes, got %d", len(chipID))
	}
	return hex.EncodeToString(chipID), nil
}

// TDXIdentity extracts the machines-map lookup key (the 16-byte PPID) from
// the PCK leaf certificate embedded in a verified TDX quote. The PPID is
// authenticated because the PCK chain is validated up to the Intel SGX root
// during quote verification; callers must only invoke this after
// verification succeeds.
func TDXIdentity(quote *tdxpb.QuoteV4) (string, error) {
	leaf, err := pckLeafCertificate(quote)
	if err != nil {
		return "", err
	}
	ext, err := pcs.PckCertificateExtensions(leaf)
	if err != nil {
		return "", fmt.Errorf("parsing PCK certificate extensions: %w", err)
	}
	ppid, err := hex.DecodeString(ext.PPID)
	if err != nil || len(ppid) != 16 {
		return "", fmt.Errorf("PCK certificate carries malformed PPID %q", ext.PPID)
	}
	// Re-encode rather than returning ext.PPID: the machines-map lookup is
	// case-sensitive and this guarantees canonical lowercase hex regardless
	// of the upstream parser's encoding.
	return hex.EncodeToString(ppid), nil
}

func pckLeafCertificate(quote *tdxpb.QuoteV4) (*x509.Certificate, error) {
	signedData := quote.GetSignedData()
	if signedData == nil {
		return nil, fmt.Errorf("quote has no signed data")
	}
	chainData := signedData.GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData()
	if chainData == nil || len(chainData.GetPckCertChain()) == 0 {
		return nil, fmt.Errorf("quote carries no PCK certificate chain (certification data type 5)")
	}

	block, _ := pem.Decode(chainData.GetPckCertChain())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PCK certificate chain is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PCK leaf certificate: %w", err)
	}
	return leaf, nil
}
