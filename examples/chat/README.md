# Chat Example

This example demonstrates how to use the Tinfoil Go SDK with chat completion models in both streaming and non-streaming modes.

## Installation

Make sure you have Go installed, then add the Tinfoil SDK to your project:

```bash
go get github.com/tinfoilsh/tinfoil-go
```

Add the required replace directive to your `go.mod`:

```go
replace github.com/google/go-sev-guest => github.com/tinfoilsh/go-sev-guest v0.0.0-20250704193550-c725e6216008
```

## Setup

1. Set your Tinfoil API key as an environment variable:

   ```bash
   export TINFOIL_API_KEY="your-tinfoil-api-key"
   ```

2. Run the example:

   ```bash
   go run main.go
   ```

## What the Example Does

The example demonstrates:

1. **Migration from OpenAI**: Shows how to create a Tinfoil client that's compatible with OpenAI Go client
2. **Streaming chat completion**: Real-time response streaming with content accumulation
3. **Non-streaming chat completion**: Standard request-response pattern
4. **Secure AI inference**: All requests are automatically routed through Tinfoil's secure enclaves

Both examples use the `llama3-3-70b` model and show proper error handling patterns.
