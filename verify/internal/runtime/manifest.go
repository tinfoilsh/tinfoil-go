package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"strings"

	cvmruntime "github.com/tinfoilsh/tinfoil-config/runtime"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"golang.org/x/mod/semver"
)

const (
	FormatVersion        = 1
	VariantFormatVersion = 2
	MeasurementSize      = 48
	MaxManifestSize      = 1 << 20
)

type Manifest struct {
	Version      string        `json:"version"`
	Measurements *Measurements `json:"igvm"`
}

type Measurements struct {
	FormatVersion int                             `json:"format_version"`
	SNPLaunch     *SNPLaunch                      `json:"snp_launch"`
	TDXLaunch     *TDXLaunch                      `json:"tdx_launch"`
	Variants      map[string]*VariantMeasurements `json:"variants,omitempty"`
}

type VariantMeasurements struct {
	SNPLaunch *SNPLaunch `json:"snp_launch"`
	TDXLaunch *TDXLaunch `json:"tdx_launch"`
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
	if _, err := m.SelectVariant(expected.Variant); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manifest) SelectVariant(selector string) (*Measurements, error) {
	if selector != "" && selector != cvmruntime.VariantGPU {
		return nil, fmt.Errorf("unsupported runtime variant %q", selector)
	}
	if m.Measurements.FormatVersion == FormatVersion {
		if selector != "" {
			return nil, fmt.Errorf("runtime format v1 does not support variant selectors")
		}
		return m.Measurements, nil
	}
	variant := (cvmruntime.Reference{Variant: selector}).ImageVariant()
	g := m.Measurements.Variants[variant]
	if g == nil {
		return nil, fmt.Errorf("runtime manifest is missing variant %q", variant)
	}
	return &Measurements{FormatVersion: VariantFormatVersion, SNPLaunch: g.SNPLaunch, TDXLaunch: g.TDXLaunch}, nil
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
	if !semver.IsValid(m.Version) || semver.Canonical(m.Version) != m.Version {
		return nil, fmt.Errorf("runtime manifest version must be a canonical semantic version")
	}
	if m.Measurements == nil {
		return nil, fmt.Errorf("runtime manifest format is unsupported")
	}
	g := m.Measurements
	switch g.FormatVersion {
	case FormatVersion:
		if len(g.Variants) != 0 {
			return nil, fmt.Errorf("runtime format v1 cannot contain variants")
		}
		if err := validateMeasurements(g.SNPLaunch, g.TDXLaunch); err != nil {
			return nil, err
		}
	case VariantFormatVersion:
		if g.SNPLaunch != nil || g.TDXLaunch != nil {
			return nil, fmt.Errorf("runtime format v2 requires variant measurements")
		}
		for _, name := range []string{cvmruntime.VariantCPU, cvmruntime.VariantGPU} {
			variant := g.Variants[name]
			if variant == nil {
				return nil, fmt.Errorf("runtime manifest is missing variant %q", name)
			}
			if err := validateMeasurements(variant.SNPLaunch, variant.TDXLaunch); err != nil {
				return nil, fmt.Errorf("runtime variant %s: %w", name, err)
			}
		}
	default:
		return nil, fmt.Errorf("runtime manifest format is unsupported")
	}
	return &m, nil
}

func validateMeasurements(snp *SNPLaunch, tdx *TDXLaunch) error {
	if snp == nil || tdx == nil {
		return fmt.Errorf("runtime manifest requires complete launch measurements")
	}
	if _, err := canonical.DecodeLowerHex("SNP measurement", snp.Measurement, MeasurementSize); err != nil {
		return err
	}
	if _, err := canonical.DecodeLowerHex("MRTD", tdx.MRTD, MeasurementSize); err != nil {
		return err
	}
	registers := tdx.Registers()
	for _, value := range registers[1:] {
		if value != strings.Repeat("0", MeasurementSize*2) {
			return fmt.Errorf("runtime manifest requires zero TDX RTMRs")
		}
	}
	return nil
}
