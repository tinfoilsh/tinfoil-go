package main

import (
	"flag"
	"log"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

var (
	outputFile = flag.String("o", "trusted_root.json", "output file")
)

func main() {
	flag.Parse()

	log.Print("Fetching latest SigStore trust root")

	trustedRootJSON, err := provenance.FetchTrustRoot()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*outputFile, trustedRootJSON, 0644); err != nil {
		log.Fatal(err)
	}
}
