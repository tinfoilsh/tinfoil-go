package provenance

// Test-only helpers for the live canary tests: they fetch published release
// artifacts through the Tinfoil GitHub proxy. Production verification never
// fetches reference values — they travel inside the attestation document.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

const githubProxy = "https://github-proxy.tinfoil.sh"

// fetchPlatformDigest returns the tag and digest of the newest published
// classic platform artifact. cvmimage's GitHub latest release is a runtime
// image and does not carry platform-endorsements-classic.json; those
// artifacts are published on platform-v* tags.
func fetchPlatformDigest() (string, string, error) {
	const pageSize = 100
	const artifactName = "platform-endorsements-classic.json"
	const tagPrefix = "platform-v"
	for page := 1; ; page++ {
		body, err := testutil.Get(fmt.Sprintf("%s/repos/%s/releases?per_page=%d&page=%d", githubProxy, platformEndorsementsRepo, pageSize, page))
		if err != nil {
			return "", "", err
		}
		var releases []struct {
			Tag        string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
			Assets     []struct {
				Name   string `json:"name"`
				Digest string `json:"digest"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(body, &releases); err != nil {
			return "", "", err
		}
		if len(releases) == 0 {
			return "", "", fmt.Errorf("no published classic platform artifact")
		}
		for _, release := range releases {
			if release.Draft || release.Prerelease || !strings.HasPrefix(release.Tag, tagPrefix) {
				continue
			}
			for _, asset := range release.Assets {
				if asset.Name != artifactName {
					continue
				}
				digest := strings.TrimPrefix(asset.Digest, "sha256:")
				if !sha256DigestRE.MatchString(digest) {
					return "", "", fmt.Errorf("platform release %q asset %q has invalid SHA-256 digest %q", release.Tag, asset.Name, asset.Digest)
				}
				return release.Tag, digest, nil
			}
		}
	}
}

func fetchAttestationBundle(repo, digest string) ([]byte, error) {
	bundleResponse, err := testutil.Get(githubProxy + "/repos/" + repo + "/attestations/sha256:" + digest)
	if err != nil {
		return nil, err
	}
	var response struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(bundleResponse, &response); err != nil {
		return nil, err
	}
	if len(response.Attestations) == 0 {
		return nil, fmt.Errorf("no attestations found for digest %s", digest)
	}
	return response.Attestations[0].Bundle, nil
}
