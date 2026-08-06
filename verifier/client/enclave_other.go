package client

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// enclaveValidPubKey checks if the endorsed TLS key fingerprint matches the
// public key of the enclave's live TLS certificate.
func enclaveValidPubKey(enclave string, expectedTLSPublicKeyFP string) error {
	// Get cert from TLS connection
	var addr string
	if strings.Contains(enclave, ":") {
		// Enclave already has a port specified
		addr = enclave
	} else {
		// Append default HTTPS port
		addr = enclave + ":443"
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to enclave: %v", err)
	}
	defer conn.Close()
	certFP, err := ConnectionCertFP(conn.ConnectionState())
	if err != nil {
		return fmt.Errorf("failed to get certificate fingerprint: %v", err)
	}

	// Check if the certificate fingerprint matches the one in the verification
	if certFP != expectedTLSPublicKeyFP {
		return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s", expectedTLSPublicKeyFP, certFP)
	}

	return nil
}
