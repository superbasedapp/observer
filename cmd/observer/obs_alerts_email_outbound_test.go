//go:build !sbo_omit_notify_email

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/alertspec"
)

// TestMachineAlertEmailHidesTheEndUser: the alert email never names a rule's
// end user (review E-82, ruling D29).
func TestMachineAlertEmailHidesTheEndUser(t *testing.T) {
	f := obsFiredAlert{
		RuleName: "spend", Metric: "cost_usd", Comparator: "gt", Threshold: 1, Value: 2,
		WindowMinutes: 60, FiredAt: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		Dimensions: alertspec.Dimensions{User: "alice@customer.example"},
	}
	if msg := fmt.Sprintf("%+v", composeAlertEmail(f, "test")); strings.Contains(msg, "alice") {
		t.Errorf("alert email names the end user: %s", msg)
	}
}
