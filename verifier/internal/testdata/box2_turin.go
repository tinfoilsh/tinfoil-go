// Package testdata provides embedded attestation fixtures shared by verifier tests.
package testdata

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
)

//go:embed box2_turin_report.b64
var box2TurinReportGzipBase64 []byte

//go:embed box2_turin_vcek.b64
var box2TurinVcekBase64 []byte

// Box2TurinReport returns a raw version 5 attestation report captured from
// production Turin hardware.
func Box2TurinReport() ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(box2TurinReportGzipBase64)))
	if err != nil {
		return nil, fmt.Errorf("decode Box2 Turin report: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("decompress Box2 Turin report: %w", err)
	}
	defer reader.Close()
	report, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read Box2 Turin report: %w", err)
	}
	return report, nil
}

// Box2TurinVcek returns the DER-encoded VCEK associated with Box2TurinReport.
func Box2TurinVcek() ([]byte, error) {
	vcek, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(box2TurinVcekBase64)))
	if err != nil {
		return nil, fmt.Errorf("decode Box2 Turin VCEK: %w", err)
	}
	return vcek, nil
}
