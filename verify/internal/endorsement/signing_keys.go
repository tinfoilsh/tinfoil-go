package endorsement

import (
	"crypto"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const publicSigningKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2Crrqxsy
nqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==
-----END PUBLIC KEY-----`

// PublicSigningKeys authenticates registry issuers, legacy public configs,
// and artifact freshness approvals.
func PublicSigningKeys() ([]crypto.PublicKey, error) {
	key, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(publicSigningKeyPEM))
	if err != nil {
		return nil, err
	}
	return []crypto.PublicKey{key}, nil
}
