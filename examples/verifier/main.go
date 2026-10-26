package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/tinfoilsh/tinfoil-go"
)

var (
	repo = flag.String("r", "tinfoilsh/confidential-model-router", "config repo, owner/name[@tag][@sha256:digest]")
	host = flag.String("e", "inference.tinfoil.sh", "enclave host")
)

func main() {
	flag.Parse()

	slog.Info("verifying enclave", "enclave", *host, "repo", *repo)
	c, err := tinfoil.NewEnclaveClient(*host, *repo, nil)
	if err != nil {
		slog.Error("creating client", "error", err)
		os.Exit(1)
	}
	verified, err := c.EnsureVerified(context.Background())
	if err != nil {
		slog.Error("verification failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("code %s@%s (sha256:%s)\n", verified.ConfigRepo(), verified.CodeTag(), verified.CodeDigest())
	fmt.Printf("fresh until %s\n", verified.FreshnessExpiresAt())
	fmt.Println(verified.EnclaveMeasurement())
}
