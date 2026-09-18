// Package strictjson decodes JSON with strict semantics shared by every
// verifier-consumed document: unknown members rejected case-sensitively,
// duplicate member names rejected everywhere, valid Unicode, no trailing data.
package strictjson

import "encoding/json/v2"

// Unmarshal decodes JSON into v, rejecting unknown members
// (case-sensitively), duplicate member names anywhere in the input,
// invalid Unicode, and trailing data.
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v, json.RejectUnknownMembers(true))
}
