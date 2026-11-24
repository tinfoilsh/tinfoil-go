package tinfoil

import (
	"context"

	"github.com/openai/openai-go/v3/option"
)

// NewClient returns an OpenAI client for Tinfoil's recommended route: a
// RouterHTTPClient that NewRouterHTTPClient creates with the default options,
// verified under ctx before it returns, and an OpenAIClient over it that
// NewOpenAIClient creates with opts, which may include WithAPIPath. An
// invalid WithAPIPath fails before any network I/O.
func NewClient(ctx context.Context, opts ...option.RequestOption) (*OpenAIClient, error) {
	if _, _, err := splitOptions(opts); err != nil {
		return nil, err
	}
	router, err := NewRouterHTTPClient(ctx, nil)
	if err != nil {
		return nil, err
	}
	return NewOpenAIClient(router, opts...)
}
