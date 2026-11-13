package endorsement

import (
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
)

func TestTimestampAuthorityRequiresCertificateBinding(t *testing.T) {
	f := sigstoretest.New(t)
	input := []byte("timestamp input")
	original, err := timestamp.ParseResponse(f.Timestamp(t, input, f.Now))
	require.NoError(t, err)
	parsed, err := pkcs7.Parse(original.RawToken)
	require.NoError(t, err)
	tstInfoOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	bindingOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	binding := func(digest []byte) pkcs7.Attribute {
		value, err := asn1.Marshal(struct{ Certs []struct{ Hash []byte } }{
			Certs: []struct{ Hash []byte }{{digest}},
		})
		require.NoError(t, err)
		return pkcs7.Attribute{Type: bindingOID, Value: asn1.RawValue{FullBytes: value}}
	}
	hash := sha256.Sum256(f.Trust.TSA.Leaf.Raw)
	validBinding := binding(hash[:])
	wrongBinding := binding(make([]byte, sha256.Size))
	for _, tc := range []struct {
		name            string
		attributes      []pkcs7.Attribute
		contentType     asn1.ObjectIdentifier
		omitCertificate bool
		valid           bool
	}{
		{name: "valid", attributes: []pkcs7.Attribute{validBinding}, contentType: tstInfoOID, valid: true},
		{name: "pinned certificate", attributes: []pkcs7.Attribute{validBinding}, contentType: tstInfoOID, omitCertificate: true, valid: true},
		{name: "missing binding", contentType: tstInfoOID},
		{name: "wrong hash", attributes: []pkcs7.Attribute{wrongBinding}, contentType: tstInfoOID},
		{name: "duplicate binding", attributes: []pkcs7.Attribute{validBinding, wrongBinding}, contentType: tstInfoOID},
		{name: "wrong content type", attributes: []pkcs7.Attribute{validBinding}, contentType: pkcs7.OIDData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := pkcs7.NewSignedData(parsed.Content)
			require.NoError(t, err)
			data.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
			data.SetContentType(tc.contentType)
			data.GetSignedData().Version = 3
			require.NoError(t, data.AddSigner(f.Trust.TSA.Leaf, f.TSAKey, pkcs7.SignerInfoConfig{
				ExtraSignedAttributes: tc.attributes, SkipCertificates: tc.omitCertificate,
			}))
			token, err := data.Finish()
			require.NoError(t, err)
			response, err := asn1.Marshal(struct {
				Status struct{ Status int }
				Token  asn1.RawValue
			}{Token: asn1.RawValue{FullBytes: token}})
			require.NoError(t, err)
			checked := timestampMaterial{&f.Trust}.TimestampingAuthorities()[0]
			result, err := checked.Verify(response, input)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, f.Now, result.Time)
			} else {
				require.Error(t, err)
			}
		})
	}
}
