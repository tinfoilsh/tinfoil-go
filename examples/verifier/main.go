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
	repo    = flag.String("r", "tinfoilsh/confidential-model-router", "GitHub repository, owner/name[@tag][@sha256:digest]")
	project = flag.String("p", "", "config registry project, org/project[@revision][@sha256:digest]")
	host    = flag.String("e", "inference.tinfoil.sh", "enclave host")
)

func main() {
	flag.Parse()

	slog.Info("verifying enclave", "enclave", *host, "repo", *repo, "project", *project)
	c, err := tinfoil.NewEnclaveHTTPClient(context.Background(), *host, tinfoil.Pin{Repo: *repo, Project: *project}, nil)
	if err != nil {
		slog.Error("verification failed", "error", err)
		os.Exit(1)
	}
	verified := c.Current()

	fmt.Printf("code %s@%s (sha256:%s)\n", verified.ConfigRepo(), verified.CodeTag(), verified.CodeDigest())
	fmt.Printf("fresh until %s\n", verified.FreshnessExpiresAt())
	fmt.Println(verified.EnclaveMeasurement())
}
