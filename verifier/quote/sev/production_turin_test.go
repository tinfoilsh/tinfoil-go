package sev

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/go-sev-guest/verify"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// These snapshots came from successfully verified v3 documents. The component
// test freezes certificate time at capture and verifies the hardware signature
// and selected platform policy offline; it does not replay freshness witnesses.
func TestProductionTurinFixtures(t *testing.T) {
	for _, host := range []string{"inf17", "inf18"} {
		t.Run(host, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", host+".json"))
			require.NoError(t, err)
			var fixture struct {
				CapturedAt time.Time     `json:"captured_at"`
				Report     string        `json:"report_base64"`
				VCEK       string        `json:"vcek_der_base64"`
				Policy     policy.Policy `json:"policy"`
			}
			require.NoError(t, json.Unmarshal(raw, &fixture))
			reportRaw, err := base64.StdEncoding.DecodeString(fixture.Report)
			require.NoError(t, err)
			report, err := sevabi.ReportToProto(reportRaw)
			require.NoError(t, err)
			require.Equal(t, uint32(5), report.Version)
			require.Equal(t, uint64(0x64), report.PlatformInfo)
			vcek, err := base64.StdEncoding.DecodeString(fixture.VCEK)
			require.NoError(t, err)
			ask, ark, err := decodeCertChain(string(askArkTurinPEM))
			require.NoError(t, err)
			product, err := productFromReport(report)
			require.NoError(t, err)
			roots, err := trustedRoots(ProductTurin)
			require.NoError(t, err)
			attestation := &sevsnp.Attestation{
				Report: report,
				CertificateChain: &sevsnp.CertificateChain{
					VcekCert: vcek,
					AskCert:  ask,
					ArkCert:  ark,
				},
				Product: product,
			}
			require.NoError(t, verify.SnpAttestation(attestation, &verify.Options{
				DisableCertFetching: true,
				TrustedRoots:        roots,
				Product:             product,
				Now:                 fixture.CapturedAt,
			}))
			q := &Quote{Identity: hex.EncodeToString(report.ChipId), attestation: attestation}
			require.Equal(t, ProductTurin, q.ProductLine())
			require.Equal(t, policy.PlatformSEVSNP, fixture.Policy.Platform)
			require.NotNil(t, fixture.Policy.SEVSNP)
			require.Equal(t, sevabi.SnpPlatformInfo{
				ECCEnabled: true, AliasCheckComplete: true, IOMMUWriteSafe: true,
			}, expectedPlatformInfo(fixture.Policy.SEVSNP))
			var reportData [64]byte
			copy(reportData[:], report.ReportData)
			expected, err := Assemble(fixture.Policy.SEVSNP, q, report.Measurement, reportData)
			require.NoError(t, err)
			require.NoError(t, expected.Validate(q))

			// The main-branch fixture required ECC=false. Both production reports
			// reject that expectation: this bit is exact policy, not a permission.
			wrongPolicy := *fixture.Policy.SEVSNP
			wrongPolicy.PlatformInfo = ptr(*wrongPolicy.PlatformInfo)
			wrongPolicy.PlatformInfo.ECCEnabled = false
			expected, err = Assemble(&wrongPolicy, q, report.Measurement, reportData)
			require.NoError(t, err)
			require.Error(t, expected.Validate(q))
		})
	}
}
