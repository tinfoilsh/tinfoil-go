package document

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

// CollateralFormat selects a verification policy, not a trust anchor.
// Each policy authenticates its required entries before using their claims.
func (d *Document) CollateralFormat() string {
	if d.collateralFormat == "" {
		return collateral.FormatV2
	}
	return d.collateralFormat
}

func decodeCollateral(format string, entries []collateral.Entry) (collateral.Set, error) {
	switch format {
	case "", collateral.FormatV2, collateral.FormatV3:
	default:
		return collateral.Set{}, fmt.Errorf("unsupported collateral format %q", format)
	}
	set, err := collateral.Decode(entries)
	if err != nil {
		return set, err
	}
	if format == collateral.FormatV3 {
		if set.SigstoreCode != nil {
			return set, fmt.Errorf("legacy code collateral is incompatible with %q", format)
		}
	} else if set.Config != nil || set.Runtime != nil {
		return set, fmt.Errorf("config and runtime collateral require %q", collateral.FormatV3)
	}
	for _, freshness := range set.Freshness {
		if (format == collateral.FormatV3) != (freshness.Format == collateral.ArtifactFreshnessV1Format) {
			return set, fmt.Errorf("freshness collateral is incompatible with %q", format)
		}
	}
	return set, nil
}
