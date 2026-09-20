package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

var (
	repo    = flag.String("r", "tinfoilsh/confidential-model-router", "config repo, owner/name[@tag][@sha256:digest]")
	enclave = flag.String("e", "inference.tinfoil.sh", "enclave host")
)

func main() {
	flag.Parse()

	slog.Info("verifying enclave", "enclave", *enclave, "repo", *repo)
	c, err := client.NewSecureClient(*enclave, *repo, nil)
	if err != nil {
		slog.Error("creating client", "error", err)
		os.Exit(1)
	}
	if _, err := c.Verify(); err != nil {
		slog.Error("verification failed", "error", err)
		os.Exit(1)
	}

	verified, err := c.VerificationJSON()
	if err != nil {
		slog.Error("failed to encode verification", "error", err)
		os.Exit(1)
	}
	slog.Info(verified)
}
