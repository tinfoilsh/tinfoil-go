package collateral

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"
)

// SigstoreRef is a decoded reference-values entry: a Sigstore bundle and the
// release it names. Repo and Tag are informational; trust comes from
// verifying Bundle against the expected signing identity and Digest.
type SigstoreRef struct {
	Repo   string
	Tag    string
	Digest string
	Bundle jsontext.Value
}

// Clone returns a deep copy of r.
func (r SigstoreRef) Clone() SigstoreRef {
	r.Bundle = slices.Clone(r.Bundle)
	return r
}

// Freshness is a decoded freshness witness: the independently signed bundle
// that attests a reference-values artifact was recently published.
type Freshness struct {
	Bundle jsontext.Value
}

// Clone returns a deep copy of f.
func (f Freshness) Clone() Freshness {
	return Freshness{Bundle: slices.Clone(f.Bundle)}
}

// sigstoreData is the data of a SigstoreCodeV1Format or
// SigstorePlatformV1Format entry.
type sigstoreData struct {
	Repo           string         `json:"repo"`
	Tag            string         `json:"tag"`
	Digest         string         `json:"digest"`
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

// freshnessData is the data of a SigstoreFreshnessV1Format entry: the
// independently signed witness bundle for the Sigstore artifact selected by
// the entry's ID.
type freshnessData struct {
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

func decodeSigstoreRef(entry *Entry) (*SigstoreRef, error) {
	var data sigstoreData
	if err := unmarshalData(entry, entry.Format, &data); err != nil {
		return nil, err
	}
	// Tag is an optional hint and Repo is checked by provenance where it
	// matters; the digest and bundle are what verification needs.
	if data.Digest == "" {
		return nil, fmt.Errorf("%s collateral entry %q is missing digest", entry.Format, entry.ID)
	}
	if err := requireBundle(entry, data.SigstoreBundle); err != nil {
		return nil, err
	}
	return &SigstoreRef{Repo: data.Repo, Tag: data.Tag, Digest: data.Digest, Bundle: data.SigstoreBundle}, nil
}

func decodeFreshness(entry *Entry) (Freshness, error) {
	var data freshnessData
	if err := unmarshalData(entry, entry.Format, &data); err != nil {
		return Freshness{}, err
	}
	if err := requireBundle(entry, data.SigstoreBundle); err != nil {
		return Freshness{}, err
	}
	return Freshness{Bundle: data.SigstoreBundle}, nil
}

// requireBundle rejects an entry whose sigstore_bundle member is missing or
// null. Whether a present bundle verifies is for provenance to judge.
func requireBundle(entry *Entry, bundle jsontext.Value) error {
	if len(bundle) == 0 || bundle.Kind() == 'n' {
		return fmt.Errorf("%s collateral entry %q is missing sigstore_bundle", entry.Format, entry.ID)
	}
	return nil
}
