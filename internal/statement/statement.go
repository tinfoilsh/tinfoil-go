package statement

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/digitorus/timestamp"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	StatementType    = "https://in-toto.io/Statement/v1"
	PayloadType      = "application/vnd.in-toto+json"
	BundleType       = "application/vnd.dev.sigstore.bundle.v0.3+json"
	DigestAlgorithm  = "sha256"
	MaxBundleSize    = 4 << 20
	MaxStatementSize = 128 << 10
	MaxTimestampSize = 64 << 10
)

func TimestampInput(domain string, core any) ([]byte, error) {
	encoded, err := json.Marshal(core)
	if err != nil {
		return nil, err
	}
	canonical := jsontext.Value(encoded)
	if err := canonical.Canonicalize(); err != nil {
		return nil, fmt.Errorf("canonicalizing endorsement core: %w", err)
	}
	return append([]byte(domain), canonical...), nil
}

// ParseTimestamp checks the response's imprint without establishing TSA trust.
func ParseTimestamp(response, input []byte) (*timestamp.Timestamp, error) {
	if len(response) == 0 || len(response) > MaxTimestampSize {
		return nil, fmt.Errorf("timestamp response size is outside allowed bounds")
	}
	ts, err := timestamp.ParseResponse(response)
	if err != nil {
		return nil, fmt.Errorf("parsing timestamp response: %w", err)
	}
	imprint := sha256.Sum256(input)
	if ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, imprint[:]) {
		return nil, fmt.Errorf("timestamp response does not match endorsement core")
	}
	return ts, nil
}

// EndorsementReference hashes the exact payload after the caller validates it.
func EndorsementReference(payload []byte) string {
	digest := sha256.Sum256(dsse.PAE(PayloadType, payload))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func KeyHint(publicKey crypto.PublicKey) (string, error) {
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return "", fmt.Errorf("approval requires an ECDSA P-256 key")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("encoding signing key: %w", err)
	}
	digest := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}
