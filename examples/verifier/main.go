package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/tinfoilsh/tinfoil-go/enclave"
)

var (
	repo = flag.String("r", "tinfoilsh/confidential-model-router", "config repo, owner/name[@tag][@sha256:digest]")
	host = flag.String("e", "inference.tinfoil.sh", "enclave host")
)

func main() {
	flag.Parse()

	slog.Info("verifying enclave", "enclave", *host, "repo", *repo)
	c, err := enclave.NewHandle(*host, *repo, nil)
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
	fmt.Println(verified)
}
