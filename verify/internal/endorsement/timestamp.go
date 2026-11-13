package endorsement

import (
	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/tinfoilsh/tinfoil-go/internal/timestampcheck"
)

type timestampMaterial struct{ root.TrustedMaterial }

func (m timestampMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
	authorities := m.TrustedMaterial.TimestampingAuthorities()
	checked := make([]root.TimestampingAuthority, len(authorities))
	for i, authority := range authorities {
		checked[i] = timestampAuthority{authority}
	}
	return checked
}

type timestampAuthority struct{ root.TimestampingAuthority }

func (a timestampAuthority) Verify(response, input []byte) (*root.Timestamp, error) {
	ts, err := timestamp.ParseResponse(response)
	if err != nil {
		return nil, err
	}
	authority, ok := a.TimestampingAuthority.(*root.SigstoreTimestampingAuthority)
	if ok {
		err = timestampcheck.Check(ts.RawToken, authority.Leaf)
	} else {
		err = timestampcheck.Check(ts.RawToken, nil)
	}
	if err != nil {
		return nil, err
	}
	return a.TimestampingAuthority.Verify(response, input)
}
