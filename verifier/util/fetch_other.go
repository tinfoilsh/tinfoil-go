package util

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

func Get(url string) ([]byte, map[string][]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("HTTP GET %s: %d %s", url, resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return body, resp.Header, nil
}

func Post(url, contentType string, reqBody []byte) ([]byte, map[string][]string, error) {
	resp, err := http.Post(url, contentType, bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("HTTP POST %s: %d %s", url, resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return body, resp.Header, nil
}
