package tinfoil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WebSearchCall represents a web search event emitted during streaming.
// These events are emitted before chat completion chunks and track search progress.
type WebSearchCall struct {
	Type   string           `json:"type"`   // Always "web_search_call"
	ID     string           `json:"id"`     // Unique identifier (e.g., "ws_abc123")
	Status string           `json:"status"` // "in_progress", "completed", "failed", or "blocked"
	Reason string           `json:"reason,omitempty"` // Present when status is "failed" or "blocked"
	Action *WebSearchAction `json:"action,omitempty"`
}

// WebSearchAction contains the search query details.
type WebSearchAction struct {
	Type  string `json:"type"`  // Always "search"
	Query string `json:"query"` // The search query
}

// Annotation represents a citation or reference in the response.
type Annotation struct {
	Type        string      `json:"type"` // "url_citation"
	URLCitation URLCitation `json:"url_citation"`
}

// URLCitation contains details about a cited source.
type URLCitation struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	Content       string `json:"content,omitempty"`
	PublishedDate string `json:"published_date,omitempty"`
}

// ReasoningItem represents a reasoning step from the agent model.
type ReasoningItem struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"` // "reasoning"
	Summary []SummaryPart  `json:"summary,omitempty"`
}

// SummaryPart represents a part of the reasoning summary.
type SummaryPart struct {
	Type string `json:"type"` // "summary_text"
	Text string `json:"text"`
}

// BlockedSearch represents a search that was blocked due to PII.
type BlockedSearch struct {
	ID     string `json:"id"`
	Query  string `json:"query"`
	Reason string `json:"reason,omitempty"`
}

// WebSearchDelta extends the standard delta with web search metadata.
// These fields appear in the metadata chunk before content chunks.
type WebSearchDelta struct {
	Content         string          `json:"content,omitempty"`
	Annotations     []Annotation    `json:"annotations,omitempty"`
	SearchReasoning string          `json:"search_reasoning,omitempty"`
	ReasoningItems  []ReasoningItem `json:"reasoning_items,omitempty"`
}

// WebSearchMessage extends the standard message with web search metadata.
// Used in non-streaming responses.
type WebSearchMessage struct {
	Content         string          `json:"content"`
	Annotations     []Annotation    `json:"annotations,omitempty"`
	SearchReasoning string          `json:"search_reasoning,omitempty"`
	ReasoningItems  []ReasoningItem `json:"reasoning_items,omitempty"`
	BlockedSearches []BlockedSearch `json:"blocked_searches,omitempty"`
}

// WebSearchStreamEvent represents either a WebSearchCall or a chat completion chunk.
// Use IsWebSearchCall() to determine the event type.
type WebSearchStreamEvent struct {
	// WebSearchCall fields (present when Type == "web_search_call")
	Type   string           `json:"type,omitempty"`
	ID     string           `json:"id,omitempty"`
	Status string           `json:"status,omitempty"`
	Reason string           `json:"reason,omitempty"`
	Action *WebSearchAction `json:"action,omitempty"`

	// Chat completion chunk fields (present when Type is empty or not "web_search_call")
	Choices []WebSearchChoice `json:"choices,omitempty"`
}

// WebSearchChoice represents a choice in the chat completion chunk with web search metadata.
type WebSearchChoice struct {
	Index        int             `json:"index"`
	Delta        *WebSearchDelta `json:"delta,omitempty"`
	FinishReason string          `json:"finish_reason,omitempty"`
}

// IsWebSearchCall returns true if this event is a web search call event.
func (e *WebSearchStreamEvent) IsWebSearchCall() bool {
	return e.Type == "web_search_call"
}

// ToWebSearchCall converts this event to a WebSearchCall.
// Returns nil if this is not a web search call event.
func (e *WebSearchStreamEvent) ToWebSearchCall() *WebSearchCall {
	if !e.IsWebSearchCall() {
		return nil
	}
	return &WebSearchCall{
		Type:   e.Type,
		ID:     e.ID,
		Status: e.Status,
		Reason: e.Reason,
		Action: e.Action,
	}
}

// WebSearchStream wraps a streaming response and parses web search events.
type WebSearchStream struct {
	reader    io.ReadCloser
	scanner   *bufio.Scanner
	current   *WebSearchStreamEvent
	err       error
	closed    bool
}

// NewWebSearchStream creates a new WebSearchStream from a streaming HTTP response body.
func NewWebSearchStream(body io.ReadCloser) *WebSearchStream {
	return &WebSearchStream{
		reader:  body,
		scanner: bufio.NewScanner(body),
	}
}

// Next advances to the next event in the stream.
// Returns true if there is a next event, false if the stream is exhausted or an error occurred.
func (s *WebSearchStream) Next() bool {
	if s.closed || s.err != nil {
		return false
	}

	for s.scanner.Scan() {
		line := s.scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}

		// Parse SSE data lines
		if data, ok := strings.CutPrefix(line, "data: "); ok {

			// Check for stream end
			if data == "[DONE]" {
				s.closed = true
				return false
			}

			// Parse the JSON event
			var event WebSearchStreamEvent
			if err := json.Unmarshal([]byte(data), &event); err != nil {
				s.err = fmt.Errorf("failed to parse stream event: %w", err)
				return false
			}

			s.current = &event
			return true
		}
	}

	if err := s.scanner.Err(); err != nil {
		s.err = err
	}

	s.closed = true
	return false
}

// Current returns the current event in the stream.
// Must be called after Next() returns true.
func (s *WebSearchStream) Current() *WebSearchStreamEvent {
	return s.current
}

// Err returns any error that occurred during streaming.
func (s *WebSearchStream) Err() error {
	return s.err
}

// Close closes the underlying reader.
func (s *WebSearchStream) Close() error {
	s.closed = true
	return s.reader.Close()
}

// ParseWebSearchMessage parses a non-streaming response body into a WebSearchMessage.
func ParseWebSearchMessage(body []byte) (*WebSearchMessage, error) {
	// The response is a chat completion object, we need to extract the message
	var response struct {
		Choices []struct {
			Message WebSearchMessage `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	return &response.Choices[0].Message, nil
}

// ParseWebSearchResponse is a convenience function that reads and parses a response body.
func ParseWebSearchResponse(body io.Reader) (*WebSearchMessage, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return ParseWebSearchMessage(data)
}

// SimulateWebSearchStream creates a WebSearchStream from raw SSE data (useful for testing).
func SimulateWebSearchStream(data string) *WebSearchStream {
	reader := io.NopCloser(bytes.NewReader([]byte(data)))
	return NewWebSearchStream(reader)
}
