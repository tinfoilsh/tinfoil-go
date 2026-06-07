//go:build !tinfoil_conformance

package main

import (
	"fmt"
	"os"
)

func cmdVerifyAttestationTDXPublic(in verifyAttestationTdxInput, quoteBytes []byte, getter *injectedGetter) int {
	fmt.Fprintln(os.Stderr, "execution_mode=public_api requires building tinfoil-conformance with -tags tinfoil_conformance")
	return exitUnsupported
}
