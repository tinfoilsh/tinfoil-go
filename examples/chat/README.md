# Tinfoil Chat Example

This example demonstrates how to use the Tinfoil client to interact with OpenAI's chat completion API in both streaming and non-streaming modes.

## Setup

1. Make sure you have Go installed and the Tinfoil repository cloned
2. Set up your environment variables (or they will be set by the example):
   ```bash
   export TINFOIL_ENCLAVE="your-enclave.tinfoil.sh"
   export TINFOIL_REPO="your-org/your-model-repo"
   ```
3. Replace the API key in the example with your actual Tinfoil API key

## Running the Example

You can run the example by executing: 
```bash
go run main.go
```

## What the Example Does

The example will:

1. Create an OpenAI client configured with Tinfoil settings

2. Demonstrate a streaming chat completion with real-time output

The code shows both the basic usage pattern and error handling for each approach. 