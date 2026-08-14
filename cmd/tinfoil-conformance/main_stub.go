//go:build !tinfoil_conformance

package main

import (
	"fmt"
	"os"
)

// The conformance adapter is a test surface, built only with
// -tags tinfoil_conformance. Production builds get this stub.
func main() {
	fmt.Fprintln(os.Stderr, "tinfoil-conformance: rebuild with -tags tinfoil_conformance")
	os.Exit(2)
}
