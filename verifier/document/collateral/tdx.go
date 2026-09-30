package collateral

import (
	"fmt"
	"maps"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/canonical"
)

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

// intelPCSData is the data of an IntelPCSV1Format entry.
type intelPCSData struct {
	Responses []pcsResponseData `json:"responses"`
}

// pcsResponseData is one captured Intel PCS response as serialized.
type pcsResponseData struct {
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
}

func decodeIntelPCS(entry *Entry) (*IntelPCS, error) {
	var data intelPCSData
	if err := unmarshalData(entry, "intel-pcs", &data); err != nil {
		return nil, err
	}
	pcs := &IntelPCS{Responses: make([]PCSResponse, 0, len(data.Responses))}
	for i, r := range data.Responses {
		body, err := canonical.DecodeBase64("body_base64", r.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("intel-pcs collateral entry %q response %d: %w", entry.ID, i, err)
		}
		pcs.Responses = append(pcs.Responses, PCSResponse{URL: r.URL, Headers: r.Headers, Body: body})
	}
	return pcs, nil
}
