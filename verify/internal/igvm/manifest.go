package igvm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"strconv"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

const (
	FormatVersion   = 1
	MeasurementSize = 48
	PlatformSubject = "platform-endorsements-igvm.json"
	MaxManifestSize = 1 << 20
)

type Manifest struct {
	Version     string        `json:"version"`
	Root        string        `json:"root"`
	Kernel      string        `json:"kernel"`
	Initrd      string        `json:"initrd"`
	Raw         string        `json:"raw"`
	CVMCompiler string        `json:"cvm_compiler"`
	IGVM        *Measurements `json:"igvm"`
}

type Measurements struct {
	FormatVersion int        `json:"format_version"`
	SNP           string     `json:"snp"`
	TDX           string     `json:"tdx"`
	SNPLaunch     *SNPLaunch `json:"snp_launch"`
	TDXLaunch     *TDXLaunch `json:"tdx_launch"`
	Cmdline       string     `json:"cmdline"`
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
	if err := expected.Validate(); err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaxManifestSize {
		return nil, fmt.Errorf("runtime manifest size is outside allowed bounds")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected.Digest {
		return nil, fmt.Errorf("runtime manifest does not match the config's digest pin")
	}
	var m Manifest
	if err := json.Unmarshal(data, &m, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parsing runtime manifest: %w", err)
	}
	if m.Version != expected.Tag || m.IGVM == nil || m.IGVM.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("runtime manifest version or IGVM format is unsupported")
	}
	g := m.IGVM
	if g.SNPLaunch == nil || g.TDXLaunch == nil || g.Cmdline == "" {
		return nil, fmt.Errorf("runtime manifest requires complete launch measurements and cmdline")
	}
	for name, value := range map[string]string{"root": m.Root, "kernel": m.Kernel, "initrd": m.Initrd, "raw": m.Raw, "cvm_compiler": m.CVMCompiler, "snp": g.SNP, "tdx": g.TDX} {
		if err := validateHex(name, value, sha256.Size); err != nil {
			return nil, err
		}
	}
	if err := validateHex("SNP measurement", g.SNPLaunch.Measurement, MeasurementSize); err != nil {
		return nil, err
	}
	if _, err := g.SNPLaunch.PolicyValue(); err != nil {
		return nil, err
	}
	if g.SNPLaunch.GuestSVN == nil || *g.SNPLaunch.GuestSVN != 0 || g.SNPLaunch.IDKeyDigest != strings.Repeat("0", MeasurementSize*2) {
		return nil, fmt.Errorf("IGVM v1 requires zero SNP guest SVN and ID-key digest")
	}
	if err := validateHex("MRTD", g.TDXLaunch.MRTD, MeasurementSize); err != nil {
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

func validateHex(name, value string, size int) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != size || strings.ToLower(value) != value {
		return fmt.Errorf("%s must be %d bytes of lowercase hexadecimal", name, size)
	}
	return nil
}
