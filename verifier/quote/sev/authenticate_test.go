package sev

import (
	"encoding/base64"
	"encoding/pem"
	"testing"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/stretchr/testify/assert"
)

func TestVerifySignatureRejectsNonExactReportSize(t *testing.T) {
	for _, size := range []int{sevabi.ReportSize - 1, sevabi.ReportSize + 1} {
		report := base64.StdEncoding.EncodeToString(make([]byte, size))
		_, err := verifySignature(report, nil, nil, nil, nil)
		assert.ErrorContains(t, err, "must be exactly", "size %d", size)
	}
}

func TestDecodeCertChainRejectsEmptyCertificate(t *testing.T) {
	emptyCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE"})
	chain := string(append(emptyCertificate, emptyCertificate...))

	_, _, err := decodeCertChain(chain)
	assert.ErrorContains(t, err, "empty CERTIFICATE block")
}
