package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/alertspec"
)

// TestMachineAlertChannelsHideTheEndUser: a rule's end user never leaves the
// machine on the generic webhook or Slack (review E-82, ruling D29); Slack
// says a user is set. The email body is pinned beside its build tag.
func TestMachineAlertChannelsHideTheEndUser(t *testing.T) {
	f := obsFiredAlert{
		RuleName: "spend", Metric: "cost_usd", Comparator: "gt", Threshold: 1, Value: 2,
		WindowMinutes: 60, FiredAt: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		Dimensions: alertspec.Dimensions{User: "alice@customer.example", Model: "gpt-5"},
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	}))
	defer srv.Close()
	if err := postAlertWebhook(context.Background(), srv.URL, f); err != nil {
		t.Fatal(err)
	}
	if got == "" || strings.Contains(got, "alice") {
		t.Errorf("webhook body leaks the end user: %s", got)
	}
	text := alertspec.SlackText(slackAlertFor(f))
	if strings.Contains(text, "alice") || !strings.Contains(text, "user="+alertspec.HiddenUser) {
		t.Errorf("slack text: %s", text)
	}
}
