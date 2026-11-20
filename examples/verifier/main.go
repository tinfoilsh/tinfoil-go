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
	repo    = flag.String("r", "tinfoilsh/confidential-model-router", "GitHub repository, owner/name[@tag][@sha256:digest]; empty accepts only v3 collateral")
	project = flag.String("p", "tinfoilsh/confidential-model-router", "config registry project, org/project[@revision][@sha256:digest]; empty accepts only v2 collateral")
	host    = flag.String("e", "inference.tinfoil.sh", "enclave host")
)

func main() {
	flag.Parse()

	slog.Info("verifying enclave", "enclave", *host, "repo", *repo, "project", *project)
	var trust tinfoil.Trust = tinfoil.EitherPin{Repo: *repo, Project: *project}
	switch {
	case *project == "":
		trust = tinfoil.RepoPin{Repo: *repo}
	case *repo == "":
		trust = tinfoil.ProjectPin{Project: *project}
	}
	c, err := tinfoil.NewEnclaveHTTPClient(context.Background(), *host, trust, nil)
	if err != nil {
		slog.Error("verification failed", "error", err)
		os.Exit(1)
	}
	verified := c.Current()

	fmt.Printf("code %s@%s (sha256:%s)\n", verified.ConfigRepo(), verified.CodeTag(), verified.CodeDigest())
	fmt.Printf("fresh until %s\n", verified.FreshnessExpiresAt())
	fmt.Println(verified.EnclaveMeasurement())
}
