package tinfoil

import (
	"context"

	"github.com/openai/openai-go/v3/option"
)

// NewClient returns an OpenAI client for Tinfoil's recommended route: a
// RouterHTTPClient that NewRouterHTTPClient creates with the default options,
// verified under ctx before it returns, and an OpenAIClient over it that
// NewOpenAIClient creates with openaiOpts.
func NewClient(ctx context.Context, openaiOpts ...option.RequestOption) (*OpenAIClient, error) {
	router, err := NewRouterHTTPClient(ctx, nil)
	if err != nil {
		return nil, err
	}
	return NewOpenAIClient(router, nil, openaiOpts...)
}
