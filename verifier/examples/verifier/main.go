package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

var (
	repo    = flag.String("r", "tinfoilsh/confidential-model-router", "config repo")
	enclave = flag.String("e", "inference.tinfoil.sh", "enclave host")
)

func main() {
	flag.Parse()

	slog.Info("verifying enclave", "enclave", *enclave, "repo", *repo)
	c := client.NewSecureClient(*enclave, *repo)
	if _, err := c.VerifyV3(); err != nil {
		slog.Error("verification failed", "error", err)
		os.Exit(1)
	}

	groundTruth, err := c.GroundTruthJSON()
	if err != nil {
		slog.Error("failed to encode ground truth", "error", err)
		os.Exit(1)
	}
	slog.Info(groundTruth)
}
