package foundry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func baseReq(endpoint string) Request {
	return Request{
		Endpoint:        endpoint,
		Deployment:      "luna",
		APIVersion:      "2024-10-21",
		APIKey:          "k",
		Dialect:         DialectChatCompletions,
		System:          "sys",
		User:            "user",
		SchemaName:      "session_enrichment",
		Schema:          json.RawMessage(`{"type":"object"}`),
		MaxOutputTokens: 512,
		Timeout:         2 * time.Second,
	}
}

func TestChatCompletionsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") != "k" {
			t.Errorf("missing api-key header")
		}
		body, _ := io.ReadAll(r.Body)
		var got map[string]any
		_ = json.Unmarshal(body, &got)
		if _, ok := got["response_format"]; !ok {
			t.Errorf("no structured-output response_format in body: %s", body)
		}
		// gpt-5.x reasoning models (the Luna deployment) reject the legacy
		// "max_tokens" and a pinned "temperature":0 with HTTP 400. The chat body
		// must speak the modern convention: max_completion_tokens, no temperature.
		if _, ok := got["max_tokens"]; ok {
			t.Errorf("legacy max_tokens present (rejected by gpt-5.x): %s", body)
		}
		if _, ok := got["max_completion_tokens"]; !ok {
			t.Errorf("no max_completion_tokens in body: %s", body)
		}
		if _, ok := got["temperature"]; ok {
			t.Errorf("temperature present (only default is accepted by gpt-5.x): %s", body)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"title\":\"t\"}"}}],"usage":{"prompt_tokens":11,"completion_tokens":7}}`))
	}))
	defer srv.Close()
	c := &AzureClient{}
	res, err := c.Complete(context.Background(), baseReq(srv.URL))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Content != `{"title":"t"}` || res.TokensIn != 11 || res.TokensOut != 7 {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestChatCompletionsQuota429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := &AzureClient{}
	if _, err := c.Complete(context.Background(), baseReq(srv.URL)); !errors.Is(err, ErrQuota) {
		t.Fatalf("want ErrQuota, got %v", err)
	}
}

func TestChatCompletionsProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	c := &AzureClient{}
	_, err := c.Complete(context.Background(), baseReq(srv.URL))
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.StatusCode != 500 {
		t.Fatalf("want *ProviderError 500, got %v", err)
	}
}

func TestChatCompletionsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &AzureClient{}
	req := baseReq(srv.URL)
	req.Timeout = 50 * time.Millisecond
	if _, err := c.Complete(context.Background(), req); !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestResponsesStoreFalseForcedAndPersistenceRejected(t *testing.T) {
	// The builder must force store:false regardless of anything.
	body := BuildResponsesBody(baseReq(""))
	if v, ok := body["store"].(bool); !ok || v {
		t.Fatalf("BuildResponsesBody did not force store:false: %+v", body["store"])
	}

	// A response indicating persistence fails the job.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"store":false`) {
			t.Errorf("request body did not carry store:false: %s", raw)
		}
		_, _ = w.Write([]byte(`{"store":true,"output_text":"{}"}`))
	}))
	defer srv.Close()
	c := &AzureClient{}
	req := baseReq(srv.URL)
	req.Dialect = DialectResponsesStoreFalse
	if _, err := c.Complete(context.Background(), req); !errors.Is(err, ErrPersistenceViolation) {
		t.Fatalf("want ErrPersistenceViolation, got %v", err)
	}
}

func TestResponsesStoreFalseSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"store":false,"output_text":"{\"title\":\"ok\"}","usage":{"input_tokens":3,"output_tokens":2}}`))
	}))
	defer srv.Close()
	c := &AzureClient{}
	req := baseReq(srv.URL)
	req.Dialect = DialectResponsesStoreFalse
	res, err := c.Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Content != `{"title":"ok"}` || res.TokensIn != 3 || res.TokensOut != 2 {
		t.Fatalf("unexpected: %+v", res)
	}
}
