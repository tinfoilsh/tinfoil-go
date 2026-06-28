package sigstore

import (
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
)

// rejectLegacyBundleFormat enforces SPEC §5.2: only the v0.3 single-certificate
// bundle layout is accepted. The legacy v0.1/v0.2 layout conveys the signing
// certificate under verificationMaterial.x509CertificateChain, which may also
// carry intermediate or root CA certificates — a misuse vector the v0.3
// single-certificate form avoids. sigstore-go parses the legacy layout (it is a
// valid oneof in the protobuf schema), so we reject it here. tinfoil only ever
// produces v0.3 bundles; this matches tinfoil-rs, which also rejects the legacy
// form.
func rejectLegacyBundleFormat(b *protobundle.Bundle) error {
	if b.GetVerificationMaterial().GetX509CertificateChain() != nil {
		return fmt.Errorf("legacy bundle format not supported: the x509CertificateChain layout requires the v0.3 single-certificate form")
	}
	return nil
}
