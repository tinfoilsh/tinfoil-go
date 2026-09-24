package document

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollateralBase64Decoders(t *testing.T) {
	want := []byte("der bytes")
	canonical := base64.StdEncoding.EncodeToString(want)

	decoders := map[string]func(string) ([]byte, error){
		"vcek_der_base64": func(v string) ([]byte, error) { return (&AMDVCEKCollateral{VCEKDERBase64: v}).VCEKDER() },
		"crl_der_base64":  func(v string) ([]byte, error) { return (&AMDCRLCollateral{CRLDERBase64: v}).CRLDER() },
		"body_base64":     func(v string) ([]byte, error) { return (&PCSResponse{BodyBase64: v}).Body() },
	}
	for field, decode := range decoders {
		t.Run(field, func(t *testing.T) {
			got, err := decode(canonical)
			require.NoError(t, err)
			assert.Equal(t, want, got)

			// Each variant decodes to the same bytes under a lenient decoder.
			for name, variant := range map[string]string{
				"embedded newline": canonical[:4] + "\n" + canonical[4:],
				"trailing CRLF":    canonical + "\r\n",
			} {
				_, err := decode(variant)
				assert.ErrorContains(t, err, field+" is not canonical base64", name)
			}
			_, err = decode("not base64!")
			assert.ErrorContains(t, err, "decoding "+field, "invalid alphabet")
		})
	}
}
