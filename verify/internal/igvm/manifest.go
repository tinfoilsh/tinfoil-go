package igvm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"strconv"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

const (
	FormatVersion   = 1
	MeasurementSize = 48
	PlatformSubject = "platform-endorsements-igvm.json"
	MaxManifestSize = 1 << 20
)

type Manifest struct {
	Version string        `json:"version"`
	IGVM    *Measurements `json:"igvm"`
}

type Measurements struct {
	FormatVersion int        `json:"format_version"`
	SNPLaunch     *SNPLaunch `json:"snp_launch"`
	TDXLaunch     *TDXLaunch `json:"tdx_launch"`
}

type SNPLaunch struct {
	Measurement string  `json:"measurement"`
	Policy      string  `json:"policy"`
	GuestSVN    *uint32 `json:"guest_svn"`
	IDKeyDigest string  `json:"id_key_digest"`
}

type TDXLaunch struct {
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
	RTMR3 string `json:"rtmr3"`
}

func (s SNPLaunch) PolicyValue() (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimPrefix(s.Policy, "0x"), 16, 64)
	if err != nil || s.Policy != "0x"+strconv.FormatUint(value, 16) {
		return 0, fmt.Errorf("SNP policy must be canonical lowercase hexadecimal with a 0x prefix")
	}
	return value, nil
}

func (s TDXLaunch) Registers() [5]string {
	return [5]string{s.MRTD, s.RTMR0, s.RTMR1, s.RTMR2, s.RTMR3}
}

func ParseManifest(data []byte, expected collateral.RuntimeReference) (*Manifest, error) {
	if len(data) == 0 || len(data) > MaxManifestSize {
		return nil, fmt.Errorf("runtime manifest size is outside allowed bounds")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected.Digest {
		return nil, fmt.Errorf("runtime manifest does not match the config's digest pin")
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing runtime manifest: %w", err)
	}
	if m.Version != expected.Tag || m.IGVM == nil || m.IGVM.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("runtime manifest version or IGVM format is unsupported")
	}
	g := m.IGVM
	if g.SNPLaunch == nil || g.TDXLaunch == nil {
		return nil, fmt.Errorf("runtime manifest requires complete launch measurements")
	}
	if _, err := canonical.DecodeLowerHex("SNP measurement", g.SNPLaunch.Measurement, MeasurementSize); err != nil {
		return nil, err
	}
	if _, err := g.SNPLaunch.PolicyValue(); err != nil {
		return nil, err
	}
	if g.SNPLaunch.GuestSVN == nil || *g.SNPLaunch.GuestSVN != 0 || g.SNPLaunch.IDKeyDigest != strings.Repeat("0", MeasurementSize*2) {
		return nil, fmt.Errorf("IGVM v1 requires zero SNP guest SVN and ID-key digest")
	}
	if _, err := canonical.DecodeLowerHex("MRTD", g.TDXLaunch.MRTD, MeasurementSize); err != nil {
		return nil, err
	}
	registers := g.TDXLaunch.Registers()
	for _, value := range registers[1:] {
		if value != strings.Repeat("0", MeasurementSize*2) {
			return nil, fmt.Errorf("IGVM v1 requires zero TDX RTMRs")
		}
	}
	return &m, nil
}
