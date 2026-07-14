package main

import (
	"flag"

	"github.com/charmbracelet/log"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

var (
	repo    = flag.String("r", "tinfoilsh/confidential-model-router", "config repo")
	enclave = flag.String("e", "inference.tinfoil.sh", "enclave host")
)

func main() {
	log.SetReportTimestamp(false)
	flag.Parse()

	log.With("enclave", *enclave, "repo", *repo).Info("Verifying enclave")
	c := client.NewSecureClient(*enclave, *repo)
	if _, err := c.VerifyV3(); err != nil {
		log.Fatalf("verification failed: %v", err)
	}

	groundTruth, err := c.GroundTruthJSON()
	if err != nil {
		log.Fatalf("failed to encode ground truth: %v", err)
	}
	log.Info(groundTruth)
}
