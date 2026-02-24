# HTTP Example

This example demonstrates how to use the Tinfoil Go SDK to make direct HTTP requests to a verified enclave, without using the OpenAI API.

```go
client, err := tinfoil.NewSecureClient(
    "inference.tinfoil.sh",
    "tinfoilsh/confidential-model-router",
)
resp, err := client.Get("https://inference.tinfoil.sh/.well-known/tinfoil-metrics")
```

## Installation

Make sure you have Go installed, then add the Tinfoil SDK to your project:

```bash
go get github.com/tinfoilsh/tinfoil-go
```

## Run

```bash
go run main.go
```
