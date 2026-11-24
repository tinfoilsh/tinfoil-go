package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verify"
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
	c, err := tinfoil.NewEnclaveHTTPClient(context.Background(), *host, trust, &tinfoil.EnclaveOptions{
		// Called for every attempt, including the retry of a failed one.
		OnVerificationAttempt: func(host string, _ *verify.VerificationReport, err error) {
			if err != nil {
				slog.Warn("verification attempt failed", "enclave", host, "error", err)
			}
		},
	})
	if err != nil {
		slog.Error("verification failed", "error", err)
		// When the verifier rejected the document, its report shows the step
		// that failed and what the steps before it established.
		var rejected *verify.VerificationError
		if errors.As(err, &rejected) {
			printReport(rejected.Report)
		}
		os.Exit(1)
	}
	// The verification that the client's requests are bound to now.
	report := c.CurrentVerification()
	if report == nil {
		slog.Error("the verification has already expired")
		os.Exit(1)
	}
	printReport(report)
	verified := report.VerifiedFacts
	fmt.Printf("code %s@%s (sha256:%s)\n", verified.ConfigRepo(), verified.CodeTag(), verified.CodeDigest())
	fmt.Printf("fresh until %s\n", verified.FreshnessExpiresAt())
	fmt.Println(verified.EnclaveMeasurement())
}

// printReport prints each step of a verification report, and for a rejected
// document the facts that were established before the failure.
func printReport(report *verify.VerificationReport) {
	for _, step := range report.Steps {
		fmt.Printf("%-10s %-8s %s\n", step.Layer, step.Status, step.Message)
	}
	facts := report.PartialFacts
	if facts == nil {
		return
	}
	if facts.Expected != nil {
		fmt.Printf("expected code %s@%s (sha256:%s)\n", facts.Expected.ConfigRepo, facts.Expected.Artifact.Tag, facts.Expected.Artifact.Digest)
		if facts.Expected.Measurement != nil {
			fmt.Println("expected", facts.Expected.Measurement)
		} else if facts.Expected.CodeMeasurement != nil {
			fmt.Println("expected", facts.Expected.CodeMeasurement)
		}
	}
	if facts.Measured != nil {
		if facts.Measured.CPU != nil {
			fmt.Println("measured", facts.Measured.CPU.Measurement)
		}
		// Only the policy step binds the keys to the enclave, so in a rejected
		// report they are only the document's claim.
		fmt.Printf("unverified TLS key fingerprint %s\n", facts.Measured.TLSPublicKeyFP)
	}
}
