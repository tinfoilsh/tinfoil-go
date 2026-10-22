package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"golang.org/x/mod/semver"
)

const (
	FormatVersion   = 1
	MeasurementSize = 48
	MaxManifestSize = 1 << 20
)

type Manifest struct {
	Version      string        `json:"version"`
	Measurements *Measurements `json:"igvm"`
}

type Measurements struct {
	FormatVersion int        `json:"format_version"`
	SNPLaunch     *SNPLaunch `json:"snp_launch"`
	TDXLaunch     *TDXLaunch `json:"tdx_launch"`
}

type SNPLaunch struct {
	Measurement string `json:"measurement"`
}

type TDXLaunch struct {
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
	RTMR3 string `json:"rtmr3"`
}

func (s TDXLaunch) Registers() [5]string {
	return [5]string{s.MRTD, s.RTMR0, s.RTMR1, s.RTMR2, s.RTMR3}
}

// ParseManifest checks that data is the manifest expected pins, then decodes
// it. The digest is checked before anything is parsed.
func ParseManifest(data []byte, expected collateral.RuntimeReference) (*Manifest, error) {
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected.Digest {
		return nil, fmt.Errorf("runtime manifest does not match the config's digest pin")
	}
	m, err := DecodeManifest(data)
	if err != nil {
		return nil, err
	}
	if m.Version != expected.Tag {
		return nil, fmt.Errorf("runtime manifest version %q does not match the config's pin %q", m.Version, expected.Tag)
	}
	return m, nil
}

// DecodeManifest checks a manifest's size and structure, without a config pin
// to match it against.
func DecodeManifest(data []byte) (*Manifest, error) {
	if len(data) == 0 || len(data) > MaxManifestSize {
		return nil, fmt.Errorf("runtime manifest size is outside allowed bounds")
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing runtime manifest: %w", err)
	}
	// Every config pins a canonical semantic version, so a manifest with any
	// other version could never match one.
	if !semver.IsValid(m.Version) || semver.Canonical(m.Version) != strings.TrimSuffix(m.Version, freshness.RuntimeGPUSuffix) {
		return nil, fmt.Errorf("runtime manifest version must be a canonical semantic version")
	}
	if m.Measurements == nil || m.Measurements.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("runtime manifest format is unsupported")
	}
	g := m.Measurements
	if g.SNPLaunch == nil || g.TDXLaunch == nil {
		return nil, fmt.Errorf("runtime manifest requires complete launch measurements")
	}
	if _, err := canonical.DecodeLowerHex("SNP measurement", g.SNPLaunch.Measurement, MeasurementSize); err != nil {
		return nil, err
	}
	if _, err := canonical.DecodeLowerHex("MRTD", g.TDXLaunch.MRTD, MeasurementSize); err != nil {
		return nil, err
	}
	registers := g.TDXLaunch.Registers()
	for _, value := range registers[1:] {
		if value != strings.Repeat("0", MeasurementSize*2) {
			return nil, fmt.Errorf("runtime format v1 requires zero TDX RTMRs")
		}
	}
	return &m, nil
}
