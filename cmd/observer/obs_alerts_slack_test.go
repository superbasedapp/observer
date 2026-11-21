package main

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

	"github.com/marmutapp/superbased-observer/internal/alertspec"
)

func TestPostSlackNeverLeaksTheURL(t *testing.T) {
	var got map[string]string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	old := slackHookCheck
	slackHookCheck = func(string) error { return nil }
	t.Cleanup(func() { slackHookCheck = old })

	hook := srv.URL + "/services/T/B/very-secret"
	f := obsFiredAlert{
		RuleName: "api errors", Metric: "error_rate", Comparator: "gt", Threshold: 0.1, Value: 0.5,
		WindowMinutes: 60, FiredAt: time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC), Dimensions: alertspec.Dimensions{Service: "api"},
	}
	if err := postSlack(context.Background(), hook, slackAlertFor(f)); err != nil {
		t.Fatalf("post: %v", err)
	}
	if !strings.Contains(got["text"], "api errors") || !strings.Contains(got["text"], "service=api") || !strings.Contains(got["text"], "this machine") {
		t.Errorf("payload: %q", got["text"])
	}
	status = http.StatusNotFound
	err := postSlack(context.Background(), hook, slackTestAlert(time.Now()))
	if err == nil || err.Error() != "slack returned 404" {
		t.Errorf("404: %v", err)
	}
	srv.Close()
	err = postSlack(context.Background(), hook, slackTestAlert(time.Now()))
	if err == nil || strings.Contains(err.Error(), "very-secret") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("unreachable error leaks the URL: %v", err)
	}
}

func TestPostSlackRefusesANonSlackURL(t *testing.T) {
	err := postSlack(context.Background(), "https://evil.example/services/x", slackTestAlert(time.Now()))
	if !errors.Is(err, alertspec.ErrSlackURL) {
		t.Fatalf("got %v", err)
	}
}
