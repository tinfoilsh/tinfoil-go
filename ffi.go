package tinfoil

// This file provides Foreign Function Interface (FFI) compatible versions of the HTTP client functions.
//
// The standard Go functions in client.go that use map[string]string for headers are not easily compatible
// with FFI bindings to other languages like Swift, C, or Rust. Maps in Go have a complex internal
// structure that doesn't translate well across language boundaries.
//
// These FFI-compatible alternatives solve the problem by:
// 1. Breaking down the request creation process into discrete steps
// 2. Using simple primitive types (int64, string) for all parameters and return values
// 3. Maintaining request state on the Go side using a unique request ID
// 4. Providing a thread-safe store to track pending requests
//
// Usage from other languages:
// 1. Call InitPostRequest/InitGetRequest to create a request and get an ID
// 2. Call AddHeader multiple times to add headers to the request
// 3. Call ExecuteRequest with the ID to execute the request and get a response
//
// This approach eliminates the need to pass complex data structures across language boundaries,
// making it much easier to create bindings to this library from other languages.

import (
	"bytes"
	"errors"
	"net/http"
	"sync"
	"time"
)

// pendingRequest stores an HTTP request with an associated ID
type pendingRequest struct {
	req *http.Request
}

// requestStore manages pending HTTP requests
type requestStore struct {
	mutex    sync.Mutex
	requests map[int64]*pendingRequest
}

// newRequestStore creates a new request store
func newRequestStore() *requestStore {
	return &requestStore{
		requests: make(map[int64]*pendingRequest),
	}
}

// add adds a request to the store and returns its ID
func (rs *requestStore) add(req *http.Request) int64 {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	id := time.Now().UnixNano()
	rs.requests[id] = &pendingRequest{req: req}
	return id
}

// get retrieves a request by ID
func (rs *requestStore) get(id int64) (*http.Request, bool) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if pr, exists := rs.requests[id]; exists {
		return pr.req, true
	}
	return nil, false
}

// remove removes a request from the store
func (rs *requestStore) remove(id int64) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	delete(rs.requests, id)
}

// Global request store
var globalRequestStore = newRequestStore()

// InitPostRequest initializes a new POST request and returns a unique request ID
func (s *SecureClient) InitPostRequest(url string, body []byte) (int64, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}

	return globalRequestStore.add(req), nil
}

// InitGetRequest initializes a new GET request and returns a unique request ID
func (s *SecureClient) InitGetRequest(url string) (int64, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	return globalRequestStore.add(req), nil
}

// AddHeader adds a header to a pending request
func (s *SecureClient) AddHeader(requestID int64, key string, value string) error {
	req, exists := globalRequestStore.get(requestID)
	if !exists {
		return errors.New("request not found")
	}

	req.Header.Set(key, value)
	return nil
}

// ExecuteRequest executes a pending request and returns the response
func (s *SecureClient) ExecuteRequest(requestID int64) (*Response, error) {
	req, exists := globalRequestStore.get(requestID)
	if !exists {
		return nil, errors.New("request not found")
	}

	// Clean up after execution
	defer globalRequestStore.remove(requestID)

	return s.makeRequest(req)
}
