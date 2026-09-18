package provenance

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

// requireExactlyOneDSSESignature enforces the Sigstore bundle rule (SPEC §5.2)
// that a DSSE-envelope bundle carries exactly one signature. sigstore-go rejects
// the empty-signatures case only indirectly — an emptied signatures array
// changes the envelope and breaks the Rekor tlog binding, so it fails as a
// transparency-log mismatch rather than a signature-count error. We check the
// count directly and early so both the empty (0) and duplicate (>1) cases fail
// with a clear, uniform reason, matching tinfoil-rs/-py/-js.
func requireExactlyOneDSSESignature(b *protobundle.Bundle) error {
	env := b.GetDsseEnvelope()
	if env == nil {
		// Not a DSSE-envelope bundle (e.g. message signature); nothing to check.
		return nil
	}
	if n := len(env.GetSignatures()); n != 1 {
		return fmt.Errorf("DSSE envelope must have exactly one signature, got %d", n)
	}
	return nil
}
