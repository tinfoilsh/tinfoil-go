package tdx

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/require"
)

// The embedded Intel SGX root is parsed on first use rather than in an init()
// that panicked, so nothing fails loudly at startup if the committed PEM is
// bad. Assert here that it parses.
func TestEmbeddedIntelRootParses(t *testing.T) {
	pool, err := embeddedIntelRoots()
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestAuthenticateRequiresVerificationTime(t *testing.T) {
	_, err := Authenticate(Evidence{}, time.Time{}, nil)
	require.ErrorContains(t, err, "verification time is required", "the library would substitute its own clock")
}

// go-tdx-guest panics on some short or inconsistent quotes. Authenticate must
// report every one of them as an error.
func TestAuthenticateRejectsMalformedQuotesWithoutPanicking(t *testing.T) {
	now := time.Date(2023, time.July, 1, 0, 0, 0, 0, time.UTC)
	// QuoteMinSize bytes of a genuine quote whose signed-data size is 0.
	minimal := bytes.Clone(tdxtestdata.RawQuote[:0x3FC])
	binary.LittleEndian.PutUint32(minimal[0x278:], 0)
	_, err := Authenticate(Evidence{Quote: minimal}, now, nil)
	require.ErrorContains(t, err, "parsing TDX quote")

	for n := range len(tdxtestdata.RawQuote) {
		_, err := Authenticate(Evidence{Quote: tdxtestdata.RawQuote[:n]}, now, nil)
		require.Error(t, err, "quote truncated to %d bytes", n)
	}
	for size := range uint32(0x200) {
		quote := bytes.Clone(tdxtestdata.RawQuote)
		binary.LittleEndian.PutUint32(quote[0x278:], size)
		_, err := Authenticate(Evidence{Quote: quote[:0x27C+int(size)]}, now, nil)
		require.Error(t, err, "signed-data size %d", size)
	}
}
