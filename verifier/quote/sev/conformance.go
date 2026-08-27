//go:build tinfoil_conformance

package sev

// The setters below mutate process-global seams and are not safe to call
// while verifications run concurrently; the conformance adapter is
// single-call by contract.

import "time"

// SetAMDRoot injects a trust anchor (ASK+ARK PEM) for authenticating synthetic
// reports; ResetAMDRoot restores the embedded Genoa root.
func SetAMDRoot(pem []byte) { amdRootPEMOverride = pem }
func ResetAMDRoot()         { amdRootPEMOverride = nil }

// SetVerificationTime pins the validity-window clock so the harness can replay
// a frozen document at its capture time; ResetVerificationTime restores time.Now.
func SetVerificationTime(t time.Time) { timeNow = func() time.Time { return t } }
func ResetVerificationTime()          { timeNow = time.Now }
