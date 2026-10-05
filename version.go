package tinfoil

import "github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"

// Version reports the Tinfoil Go SDK version: the version of this module the
// program was built with, or "devel" for a build from a source checkout.
func Version() string { return sdkinfo.Version() }
