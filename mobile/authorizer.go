package mobile

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// ConfigAuthorizer decides whether a deployment's config is authorized, in
// place of verifying the config's endorsement. Implement it in Swift and pass
// it to NewVerifierWithConfigAuthorizer.
//
// AuthorizeConfig receives the config material from the attestation document
// as JSON, which is untrusted. Byte strings are standard base64 of the exact
// bytes in the document, including the Sigstore bundle's JSON:
//
//	{
//	  "config": "<standard base64 of the config bytes>",
//	  "reference": "sha256:<hex>",            // absent for plain config
//	  "sigstore_bundle": "<base64>",          // absent for plain config
//	  "issuer_certificate_der": "<base64>"    // absent unless certified
//	}
//
// Return nil to authorize the config, or an error to reject it; the document
// then fails verification at the provenance layer with the error's message.
// The runtime, platform and hardware are still verified. Approving a config
// authenticates no registry, name or approval time.
//
// AuthorizeConfig runs synchronously inside Verifier.Verify, on the thread
// that called it, and may run on several threads at once.
type ConfigAuthorizer interface {
	AuthorizeConfig(endorsementJSON string) error
}

// configEndorsementJSON is the payload ConfigAuthorizer receives.
type configEndorsementJSON struct {
	Config               string `json:"config"`
	Reference            string `json:"reference,omitempty"`
	SigstoreBundle       string `json:"sigstore_bundle,omitempty"`
	IssuerCertificateDER string `json:"issuer_certificate_der,omitempty"`
}

// authorizeWith adapts a ConfigAuthorizer to the verifier's callback.
func authorizeWith(authorizer ConfigAuthorizer) func(collateral.ConfigEndorsement) error {
	return func(endorsement collateral.ConfigEndorsement) error {
		payload := configEndorsementJSON{
			Config:    base64.StdEncoding.EncodeToString(endorsement.Config),
			Reference: endorsement.Reference,
		}
		if len(endorsement.Bundle) != 0 {
			payload.SigstoreBundle = base64.StdEncoding.EncodeToString(endorsement.Bundle)
		}
		if endorsement.Issuer != nil {
			payload.IssuerCertificateDER = base64.StdEncoding.EncodeToString(endorsement.Issuer)
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encoding config endorsement: %w", err)
		}
		return authorizer.AuthorizeConfig(string(encoded))
	}
}
