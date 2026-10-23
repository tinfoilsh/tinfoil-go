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
	verified, err := c.Verify()
	if err != nil {
		slog.Error("verification failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("code %s@%s (sha256:%s)\n", verified.ConfigRepo(), verified.CodeTag(), verified.CodeDigest())
	fmt.Printf("fresh until %s\n", verified.FreshnessExpiresAt())
	fmt.Println(verified.EnclaveMeasurement())
}
