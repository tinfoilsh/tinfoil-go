package main

import (
	"encoding/json"
	"log"

	"github.com/tinfoilsh/tinfoil-go/client"
)

func main() {
	tinfoilClient, err := client.NewDefaultClient(nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	log.Printf("Connected to enclave: %s", tinfoilClient.Enclave())

	body := []byte(`{"model":"gpt-oss-120b","messages":[{"role":"user","content":"What is 2+2?"}]}`)

	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer <TINFOIL_API_KEY>",
	}

	headersJSON, _ := json.Marshal(headers)
	resp, err := tinfoilClient.Request("POST", "/v1/chat/completions", string(headersJSON), body)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}

	log.Printf("Response: %s", string(resp.Body))
}
