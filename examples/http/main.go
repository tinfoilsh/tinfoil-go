package main

import (
	"fmt"
	"io"
	"log"

	tinfoil "github.com/tinfoilsh/tinfoil-go"
)

func main() {
	// Create a secure client pinned to the enclave and source repo.
	// Attestation is verified automatically during client creation.
	client, err := tinfoil.NewSecureClient(
		"inference.tinfoil.sh",
		"tinfoilsh/confidential-model-router",
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Get(), Post(), and Do() use the TLS-pinned HTTP client directly.
	resp, err := client.Get("https://inference.tinfoil.sh/.well-known/tinfoil-metrics")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read body: %v", err)
	}
	fmt.Println(string(body))
}
