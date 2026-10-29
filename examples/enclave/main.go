package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/tinfoilsh/tinfoil-go"
)

func main() {
	client, err := tinfoil.NewEnclaveHTTPClient(context.Background(), "inference.tinfoil.sh", "tinfoilsh/confidential-model-router", nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	log.Printf("Connected to enclave: %s", client.BaseURL())

	body := []byte(`{"model":"gpt-oss-120b","messages":[{"role":"user","content":"What is 2+2?"}]}`)
	req, err := http.NewRequest(http.MethodPost, client.BaseURL()+"v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("TINFOIL_API_KEY"))

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("reading response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("request failed: %s: %s", resp.Status, response)
	}

	log.Printf("Response: %s", response)
}
