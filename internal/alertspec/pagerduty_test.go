package alertspec

import (
	"encoding/json"
	"strings"
	"testing"
)

const testPDKey = "abcdefABCDEF0123456789abcdefABCD"

func TestValidPagerDutyRoutingKey(t *testing.T) {
	for _, c := range []struct {
		key string
		ok  bool
	}{
		{"", true},
		{testPDKey, true},
		{testPDKey[:31], false},
		{testPDKey + "x", false},
		{strings.Repeat("a", 31) + "-", false},
		{strings.Repeat("a", 31) + "é", false},
	} {
		err := ValidPagerDutyRoutingKey(c.key)
		if (err == nil) != c.ok {
			t.Errorf("%q: err=%v", c.key, err)
		}
		if err != nil && c.key != "" && strings.Contains(err.Error(), c.key) {
			t.Errorf("error leaks the key: %v", err)
		}
	}
}

func TestPagerDutyDedupKey(t *testing.T) {
	d := Dimensions{User: "alice@example", Service: "api"}
	k := PagerDutyDedupKey("org1", "rule1", d)
	if k != PagerDutyDedupKey("org1", "rule1", d) {
		t.Fatal("dedup key must be stable")
	}
	if !strings.HasPrefix(k, "sbo-") || len(k) != 44 {
		t.Fatalf("shape: %q", k)
	}
	if strings.Contains(k, "alice") {
		t.Fatal("dedup key leaks the end user")
	}
	for _, other := range []string{
		PagerDutyDedupKey("org2", "rule1", d),
		PagerDutyDedupKey("org1", "rule2", d),
		PagerDutyDedupKey("org1", "rule1", Dimensions{User: "bob", Service: "api"}),
		PagerDutyDedupKey("org1", "rule1", Dimensions{}),
	} {
		if other == k {
			t.Fatal("dedup keys must differ by scope, rule and dimensions")
		}
	}
}

func TestPagerDutyEvent(t *testing.T) {
	a := SlackAlert{
		Event: "fired", RuleName: "errors", Metric: "error_rate", Comparator: "gte", Threshold: 0.05, Value: 0.08,
		Window: "60 minute(s)", Dimensions: Dimensions{Service: "api"}, Source: "Acme", FiredAt: "2026-11-20T10:00:00Z",
	}
	b, err := PagerDutyEvent(testPDKey, "sbo-x", a)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["event_action"] != "trigger" || got["dedup_key"] != "sbo-x" || got["routing_key"] != testPDKey {
		t.Fatalf("body: %s", b)
	}
	p := got["payload"].(map[string]any)
	if p["severity"] != "error" || p["source"] != "Acme" || !strings.Contains(p["summary"].(string), "error_rate 0.08 >= 0.05") {
		t.Fatalf("payload: %v", p)
	}
	if p["custom_details"].(map[string]any)["dimension_service"] != "api" {
		t.Fatalf("details: %v", p)
	}

	// R-C19: the end user a rule names never reaches PagerDuty.
	withUser := a
	withUser.Dimensions.User = "alice@example.com"
	ub, err := PagerDutyEvent(testPDKey, "sbo-x", withUser)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ub), "alice") || !strings.Contains(string(ub), `"dimension_user":"`+PagerDutyHiddenUser+`"`) {
		t.Fatalf("end user in the PagerDuty body: %s", ub)
	}

	a.Event = "resolved"
	b, err = PagerDutyEvent(testPDKey, "sbo-x", a)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	_ = json.Unmarshal(b, &got)
	if got["event_action"] != "resolve" || got["payload"] != nil {
		t.Fatalf("resolve: %s", b)
	}

	a.Event = "test"
	b, _ = PagerDutyEvent(testPDKey, "sbo-t", a)
	if !strings.Contains(string(b), `"severity":"info"`) {
		t.Fatalf("test: %s", b)
	}

	if _, err := PagerDutyEvent("", "sbo-x", a); err == nil {
		t.Fatal("empty key must be refused")
	}
	if _, err := PagerDutyEvent(testPDKey, "", a); err == nil {
		t.Fatal("empty dedup key must be refused")
	}
	a.Event, a.RuleName = "fired", strings.Repeat("r", 2000)
	b, _ = PagerDutyEvent(testPDKey, "sbo-x", a)
	got = nil
	_ = json.Unmarshal(b, &got)
	if n := len(got["payload"].(map[string]any)["summary"].(string)); n > maxPagerDutySummary {
		t.Fatalf("summary %d bytes", n)
	}
}
