package tinfoil

import (
	"testing"
)

func TestWebSearchCallParsing(t *testing.T) {
	// Simulate SSE stream with web search events
	sseData := `data: {"type":"web_search_call","id":"ws_abc123","status":"in_progress","action":{"type":"search","query":"latest quantum computing news 2026"}}

data: {"type":"web_search_call","id":"ws_abc123","status":"completed","action":{"type":"search","query":"latest quantum computing news 2026"}}

data: {"choices":[{"index":0,"delta":{"annotations":[{"type":"url_citation","url_citation":{"title":"Quantum News","url":"https://example.com/quantum"}}]}}]}

data: {"choices":[{"index":0,"delta":{"content":"Here are the latest developments..."}}]}

data: {"choices":[{"index":0,"delta":{"content":" in quantum computing."},"finish_reason":"stop"}]}

data: [DONE]
`

	stream := SimulateWebSearchStream(sseData)
	defer stream.Close()

	var events []*WebSearchStreamEvent
	for stream.Next() {
		event := stream.Current()
		events = append(events, event)
	}

	if err := stream.Err(); err != nil {
		t.Fatalf("Stream error: %v", err)
	}

	if len(events) != 5 {
		t.Fatalf("Expected 5 events, got %d", len(events))
	}

	// Check first event (web search in_progress)
	if !events[0].IsWebSearchCall() {
		t.Error("First event should be a web search call")
	}
	wsCall := events[0].ToWebSearchCall()
	if wsCall.Status != "in_progress" {
		t.Errorf("Expected status 'in_progress', got '%s'", wsCall.Status)
	}
	if wsCall.Action == nil || wsCall.Action.Query != "latest quantum computing news 2026" {
		t.Error("Web search action query mismatch")
	}

	// Check second event (web search completed)
	if !events[1].IsWebSearchCall() {
		t.Error("Second event should be a web search call")
	}
	wsCall2 := events[1].ToWebSearchCall()
	if wsCall2.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", wsCall2.Status)
	}

	// Check third event (annotations)
	if events[2].IsWebSearchCall() {
		t.Error("Third event should not be a web search call")
	}
	if len(events[2].Choices) == 0 {
		t.Fatal("Third event should have choices")
	}
	delta := events[2].Choices[0].Delta
	if delta == nil || len(delta.Annotations) == 0 {
		t.Fatal("Third event should have annotations")
	}
	if delta.Annotations[0].Type != "url_citation" {
		t.Errorf("Expected annotation type 'url_citation', got '%s'", delta.Annotations[0].Type)
	}
	if delta.Annotations[0].URLCitation.Title != "Quantum News" {
		t.Errorf("Expected citation title 'Quantum News', got '%s'", delta.Annotations[0].URLCitation.Title)
	}

	// Check fourth event (content)
	if events[3].Choices[0].Delta.Content != "Here are the latest developments..." {
		t.Error("Fourth event content mismatch")
	}

	// Check fifth event (content with finish_reason)
	if events[4].Choices[0].Delta.Content != " in quantum computing." {
		t.Error("Fifth event content mismatch")
	}
	if events[4].Choices[0].FinishReason != "stop" {
		t.Errorf("Expected finish_reason 'stop', got '%s'", events[4].Choices[0].FinishReason)
	}
}

func TestWebSearchBlockedEvent(t *testing.T) {
	sseData := `data: {"type":"web_search_call","id":"ws_def456","status":"blocked","reason":"SSN detected","action":{"type":"search","query":"search for John Smith SSN 123-45-6789"}}

data: [DONE]
`

	stream := SimulateWebSearchStream(sseData)
	defer stream.Close()

	if !stream.Next() {
		t.Fatal("Expected at least one event")
	}

	event := stream.Current()
	if !event.IsWebSearchCall() {
		t.Error("Event should be a web search call")
	}

	wsCall := event.ToWebSearchCall()
	if wsCall.Status != "blocked" {
		t.Errorf("Expected status 'blocked', got '%s'", wsCall.Status)
	}
	if wsCall.Reason != "SSN detected" {
		t.Errorf("Expected reason 'SSN detected', got '%s'", wsCall.Reason)
	}
}

func TestParseWebSearchMessage(t *testing.T) {
	responseJSON := `{
		"choices": [{
			"message": {
				"content": "The capital of France is Paris.",
				"annotations": [{
					"type": "url_citation",
					"url_citation": {
						"title": "France Wikipedia",
						"url": "https://en.wikipedia.org/wiki/France",
						"content": "Paris is the capital..."
					}
				}],
				"search_reasoning": "User asked about geography, searching for factual information.",
				"reasoning_items": [{
					"id": "reason_123",
					"type": "reasoning",
					"summary": [{
						"type": "summary_text",
						"text": "Looking up capital city information"
					}]
				}]
			}
		}]
	}`

	msg, err := ParseWebSearchMessage([]byte(responseJSON))
	if err != nil {
		t.Fatalf("Failed to parse message: %v", err)
	}

	if msg.Content != "The capital of France is Paris." {
		t.Errorf("Content mismatch: %s", msg.Content)
	}

	if len(msg.Annotations) != 1 {
		t.Fatalf("Expected 1 annotation, got %d", len(msg.Annotations))
	}

	if msg.Annotations[0].URLCitation.Title != "France Wikipedia" {
		t.Errorf("Annotation title mismatch: %s", msg.Annotations[0].URLCitation.Title)
	}

	if msg.SearchReasoning != "User asked about geography, searching for factual information." {
		t.Errorf("Search reasoning mismatch: %s", msg.SearchReasoning)
	}

	if len(msg.ReasoningItems) != 1 {
		t.Fatalf("Expected 1 reasoning item, got %d", len(msg.ReasoningItems))
	}

	if msg.ReasoningItems[0].Type != "reasoning" {
		t.Errorf("Reasoning item type mismatch: %s", msg.ReasoningItems[0].Type)
	}

	if len(msg.ReasoningItems[0].Summary) != 1 {
		t.Fatalf("Expected 1 summary part, got %d", len(msg.ReasoningItems[0].Summary))
	}

	if msg.ReasoningItems[0].Summary[0].Text != "Looking up capital city information" {
		t.Errorf("Summary text mismatch: %s", msg.ReasoningItems[0].Summary[0].Text)
	}
}

func TestParseWebSearchMessageWithBlockedSearches(t *testing.T) {
	responseJSON := `{
		"choices": [{
			"message": {
				"content": "I cannot search for that information.",
				"blocked_searches": [{
					"id": "ws_blocked1",
					"query": "search for account number 1234567890",
					"reason": "Bank account number detected"
				}]
			}
		}]
	}`

	msg, err := ParseWebSearchMessage([]byte(responseJSON))
	if err != nil {
		t.Fatalf("Failed to parse message: %v", err)
	}

	if len(msg.BlockedSearches) != 1 {
		t.Fatalf("Expected 1 blocked search, got %d", len(msg.BlockedSearches))
	}

	if msg.BlockedSearches[0].Query != "search for account number 1234567890" {
		t.Errorf("Blocked search query mismatch: %s", msg.BlockedSearches[0].Query)
	}

	if msg.BlockedSearches[0].Reason != "Bank account number detected" {
		t.Errorf("Blocked search reason mismatch: %s", msg.BlockedSearches[0].Reason)
	}
}

func TestToWebSearchCallNil(t *testing.T) {
	// A non-web-search event should return nil from ToWebSearchCall
	event := &WebSearchStreamEvent{
		Choices: []WebSearchChoice{
			{Delta: &WebSearchDelta{Content: "Hello"}},
		},
	}

	if event.IsWebSearchCall() {
		t.Error("Event should not be a web search call")
	}

	if event.ToWebSearchCall() != nil {
		t.Error("ToWebSearchCall should return nil for non-web-search events")
	}
}

func TestEmptyStream(t *testing.T) {
	sseData := `data: [DONE]
`

	stream := SimulateWebSearchStream(sseData)
	defer stream.Close()

	if stream.Next() {
		t.Error("Empty stream should not have any events")
	}

	if stream.Err() != nil {
		t.Errorf("Empty stream should not have errors: %v", stream.Err())
	}
}

func TestStreamWithComments(t *testing.T) {
	sseData := `: this is a comment
data: {"choices":[{"index":0,"delta":{"content":"Hello"}}]}

: another comment
data: [DONE]
`

	stream := SimulateWebSearchStream(sseData)
	defer stream.Close()

	count := 0
	for stream.Next() {
		count++
	}

	if count != 1 {
		t.Errorf("Expected 1 event (comments should be skipped), got %d", count)
	}
}
