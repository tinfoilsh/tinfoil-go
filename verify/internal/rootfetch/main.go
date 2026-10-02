// Command rootfetch refreshes the embedded Sigstore trusted-root document
// from the Sigstore TUF repository. It is a maintenance tool: the verifier
// itself only ever uses the embedded copy.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

var outputFile = flag.String("o", "trusted_root.json", "output file")

func main() {
	flag.Parse()

	log.Print("Fetching latest Sigstore trust root")

	client, err := tuf.New(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil {
		log.Fatal(err)
	}
	trustedRootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*outputFile, trustedRootJSON, 0644); err != nil {
		log.Fatal(err)
	}
}
