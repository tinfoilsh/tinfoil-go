package document

import (
	"maps"
	"slices"
)

// CPUEndorsements is the decoded vendor collateral that chains the document's
// CPU evidence to its vendor root. A nil field means the document carries no
// such collateral; which fields are required depends on the evidence format,
// and CPU-evidence authentication rejects evidence missing one.
type CPUEndorsements struct {
	AMDVCEK  *AMDVCEK
	AMDCRL   *AMDCRL
	IntelPCS *IntelPCS
}

// Clone returns a deep copy of e.
func (e CPUEndorsements) Clone() CPUEndorsements {
	return CPUEndorsements{AMDVCEK: e.AMDVCEK.Clone(), AMDCRL: e.AMDCRL.Clone(), IntelPCS: e.IntelPCS.Clone()}
}

// IntelPCS is decoded intel-pcs collateral: Intel PCS responses captured so a
// verifier replays them instead of fetching.
type IntelPCS struct {
	Responses []PCSResponse
}

// Clone returns a deep copy of p, or nil for a nil p.
func (p *IntelPCS) Clone() *IntelPCS {
	if p == nil {
		return nil
	}
	var responses []PCSResponse
	if p.Responses != nil {
		responses = make([]PCSResponse, len(p.Responses))
		for i, r := range p.Responses {
			responses[i] = r.Clone()
		}
	}
	return &IntelPCS{Responses: responses}
}

// PCSResponse is one decoded captured Intel PCS response. Headers are kept
// because Intel delivers issuer chains in response headers.
type PCSResponse struct {
	URL     string
	Headers map[string][]string
	Body    []byte
}

// Clone returns a deep copy of r.
func (r PCSResponse) Clone() PCSResponse {
	var headers map[string][]string
	if r.Headers != nil {
		headers = maps.Clone(r.Headers)
		for name, values := range headers {
			headers[name] = slices.Clone(values)
		}
	}
	return PCSResponse{URL: r.URL, Headers: headers, Body: slices.Clone(r.Body)}
}

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

// CPUEndorsements returns a copy of the endorsement collateral the document's
// CPU evidence format uses, for the reserved "cpu" subject, as Parse decoded
// it. Collateral the document does not carry is left nil.
func (d *Document) CPUEndorsements() CPUEndorsements {
	var en CPUEndorsements
	switch d.evidence.Format {
	case SEVSNPReportV1Format:
		en = CPUEndorsements{AMDVCEK: d.collateral.amdVCEK, AMDCRL: d.collateral.amdCRL}
	case TDXQuoteV1Format:
		en = CPUEndorsements{IntelPCS: d.collateral.intelPCS}
	}
	return en.Clone()
}
