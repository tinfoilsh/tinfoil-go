package provenance

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// sctLogIDsInCertDER hand-parses the embedded Signed Certificate Timestamp
// list (OID 1.3.6.1.4.1.11129.2.4.2) and returns each SCT's 32-byte CT log ID,
// in order. The SCT extension wraps a SerializedSCTList; each SerializedSCT is
// an RFC 6962 SignedCertificateTimestamp whose first bytes are
// version(1) || log_id(32) || timestamp(8) || ... — so the log ID is bytes
// [1:33] of each entry. Mirrors CountSCTsInCertDER's parsing.
func sctLogIDsInCertDER(certDER []byte) ([][]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	sctOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(sctOID) {
			continue
		}
		// ext.Value is the outer OCTET STRING contents x509 already unwrapped;
		// the inner content is another OCTET STRING wrapping the
		// SerializedSCTList (a uint16 length prefix + the SCT entries).
		var inner []byte
		if _, err := asn1.Unmarshal(ext.Value, &inner); err != nil {
			return nil, err
		}
		if len(inner) < 2 {
			return nil, fmt.Errorf("SCT extension body too short")
		}
		totalLen := int(inner[0])<<8 | int(inner[1])
		body := inner[2:]
		if totalLen <= len(body) {
			body = body[:totalLen]
		}
		var ids [][]byte
		i := 0
		for i+2 <= len(body) {
			sctLen := int(body[i])<<8 | int(body[i+1])
			i += 2
			if i+sctLen > len(body) {
				return nil, fmt.Errorf("SCT extension parse: entry beyond body")
			}
			sct := body[i : i+sctLen]
			// version(1) || log_id(32) || ...
			if len(sct) >= 33 {
				id := make([]byte, 32)
				copy(id, sct[1:33])
				ids = append(ids, id)
			}
			i += sctLen
		}
		return ids, nil
	}
	return nil, nil
}

// checkDuplicateSCTLogs enforces the SPEC §5.2 anti-replay guard: a leaf
// certificate whose embedded SCT list contains two or more SCTs sharing the
// same CT log ID MUST be rejected, so a single (compromised or replayed) log
// cannot contribute more than one SCT toward the requirement. This mirrors
// tinfoil-rs (transparency HashSet) and tinfoil-js. sigstore-go itself dedups
// SCTs by log ID rather than rejecting, so we add this guard on top.
//
// A parse failure returns nil — a malformed SCT extension is the main
// verifier's concern, not this guard's.
func checkDuplicateSCTLogs(certDER []byte) error {
	ids, err := sctLogIDsInCertDER(certDER)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[string(id)] {
			return fmt.Errorf("duplicate SCT log id: leaf certificate carries multiple SCTs from the same CT log")
		}
		seen[string(id)] = true
	}
	return nil
}
