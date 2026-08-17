//go:build tinfoil_conformance

package tdx

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// SetIntelRoot injects an Intel SGX root (PEM) for authenticating synthetic
// quotes; ResetIntelRoot restores the embedded root.
func SetIntelRoot(rootPEM []byte) error {
	pool, err := poolFromPEM(rootPEM)
	if err != nil {
		return err
	}
	intelRootCertPool = pool
	return nil
}

func ResetIntelRoot() {
	pool, err := poolFromPEM(sgxRootCACertPEM)
	if err != nil {
		panic("embedded Intel root failed to parse: " + err.Error()) // matches init()
	}
	intelRootCertPool = pool
}

func poolFromPEM(rootPEM []byte) (*x509.CertPool, error) {
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		return nil, fmt.Errorf("intel SGX root PEM carried no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// SetVerificationTime pins the validity-window clock so the harness can replay
// a frozen document at its capture time; ResetVerificationTime restores time.Now.
func SetVerificationTime(t time.Time) { timeNow = func() time.Time { return t } }
func ResetVerificationTime()          { timeNow = time.Now }
