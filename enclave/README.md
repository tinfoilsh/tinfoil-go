# Tinfoil Enclave Handle

`enclave.Handle` fetches an enclave's attestation document, verifies it
with the [verifier](../verify/README.md), and binds HTTP traffic to the
attested keys. Fetching, caching, expiry and retries live here; the verifier
itself performs no I/O.

## Quick Start
```go
package main

import (
	"log"

	"github.com/tinfoilsh/tinfoil-go/enclave"
)

func main() {
	handle, err := enclave.NewHandle("enclave.example.com", "org/repo", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Attestation happens automatically on the first request.
	resp, err := handle.Request("GET", "/api/data", "", nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s: %s", resp.Status, resp.Body)
}
```

`handle.HTTPClient()` returns the underlying pinned `*http.Client`, and
`handle.Verify()` returns the verified measurements and keys.

## Pinning and refresh

The TLS pin runs for direct HTTPS and HTTPS-over-CONNECT connections. Every
client and transport from one `Handle` shares one verification and checks its
`FreshnessExpiresAt` deadline before admitting each request, including
redirects and key-rotation retries. After the deadline, new requests wait for
a successful refresh; a request admitted earlier, including a streaming
response, may finish. There is no background refresh.

## Verification options

`enclave.Options` carries the same policy as
[`verify.NewVerifier`](../verify/README.md#verification-options) as a struct
the Swift bindings can construct:

```go
import (
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// newPinnedHandle also requires the enclave's RTMR3 to equal rtmr3 (hex).
func newPinnedHandle(rtmr3 string) (*enclave.Handle, error) {
	opts := enclave.Options{
		PinnedRegisters: &measurement.Measurement{
			Type:      measurement.TdxGuestV2,
			Registers: []string{4: rtmr3},
		},
	}
	return enclave.NewHandle("enclave.example.com", "org/repo", &opts)
}
```

To trust a local config instead of a registry endorsement, set
`EmbeddedConfig: &verify.EmbeddedConfig{Bytes: configBytes}` and pass an empty
repo. Runtime and platform endorsements and freshness remain required, and
the config bytes must come from trusted caller configuration.

## Auditing the Handle Code

- Fetching, caching and freshness enforcement: this package.
- Per-connection TLS pinning: `roundtrip.go`.
