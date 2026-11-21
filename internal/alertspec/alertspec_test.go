package alertspec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDimensionsZeroNormalizePairs(t *testing.T) {
	if !(Dimensions{}).IsZero() {
		t.Fatal("zero value must be IsZero")
	}
	d := Dimensions{Model: " gpt ", Service: "api "}.Normalize()
	if d.Model != "gpt" || d.Service != "api" || d.IsZero() {
		t.Fatalf("normalize: %+v", d)
	}
	got := d.Pairs()
	if len(got) != 2 || got[0] != [2]string{"model", "gpt"} || got[1] != [2]string{"service", "api"} {
		t.Fatalf("pairs: %v", got)
	}
}

func TestDimensionsValidate(t *testing.T) {
	cases := []struct {
		name string
		d    Dimensions
		ok   bool
	}{
		{"empty", Dimensions{}, true},
		{"set", Dimensions{Model: "m", User: "u", Tag: "t", Service: "s"}, true},
		{"too long", Dimensions{Tag: strings.Repeat("x", MaxDimensionLen+1)}, false},
		{"at bound", Dimensions{Tag: strings.Repeat("x", MaxDimensionLen)}, true},
		{"control", Dimensions{User: "a\nb"}, false},
	}
	for _, c := range cases {
		err := c.d.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
		if err != nil && strings.Contains(err.Error(), "a\nb") {
			t.Errorf("%s: error carries the value", c.name)
		}
	}
}

func TestValidSlackWebhookURL(t *testing.T) {
	cases := []struct {
		url string
		ok  bool
	}{
		{"", true},
		{"https://hooks.slack.com/services/T000/B000/XXXX", true},
		{"https://hooks.slack-gov.com/services/T000/B000/XXXX", true},
		{"https://hooks.slack.com/workflows/T000/A000/1/abc", true},
		{"https://hooks.slack.com/triggers/T000/1/abc", true},
		{"http://hooks.slack.com/services/T000/B000/XXXX", false},
		{"https://hooks.slack.com:8443/services/T/B/X", false},
		{"https://user:pw@hooks.slack.com/services/T/B/X", false},
		{"https://evil.example/services/T/B/X", false},
		{"https://hooks.slack.com.evil.example/services/T/B/X", false},
		{"https://hooks.slack.com/", false},
		{"https://hooks.slack.com/services/", false},
		{"not a url", false},
	}
	for _, c := range cases {
		err := ValidSlackWebhookURL(c.url)
		if (err == nil) != c.ok {
			t.Errorf("%q: err=%v", c.url, err)
		}
		if err != nil && c.url != "" && !strings.HasSuffix(ErrSlackURL.Error(), c.url+" URL") && strings.Contains(err.Error(), c.url) {
			t.Errorf("%q: error carries the URL", c.url)
		}
	}
}

func TestSlackPayload(t *testing.T) {
	b, err := SlackPayload(SlackAlert{
		Event: "fired", RuleName: "<!channel> errs & co", Metric: "error_rate", Comparator: "gte",
		Threshold: 0.05, Value: 0.125, Window: "60 minute(s)",
		Dimensions: Dimensions{Service: "api"}, Source: "acme", FiredAt: "2026-11-19T10:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	text := body["text"]
	for _, want := range []string{"fired", "&lt;!channel&gt; errs &amp; co", "`error_rate` is 0.125 (threshold >= 0.05) over 60 minute(s)", "Dimensions: service=api", "Source: acme", "At: 2026-11-19T10:00:00Z"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "<!channel>") {
		t.Error("mention not escaped")
	}
	test := SlackText(SlackAlert{Event: "test", RuleName: "x"})
	if strings.Contains(test, "threshold") || !strings.Contains(test, "test message") {
		t.Errorf("test text: %s", test)
	}
	resolved := SlackText(SlackAlert{Event: "resolved", RuleName: "x", Metric: "cost_usd"})
	if !strings.Contains(resolved, "resolved") || !strings.Contains(resolved, "(threshold > 0)") {
		t.Errorf("resolved text: %s", resolved)
	}
}

// TestOutboundHidesTheEndUser: every outbound rendering (Slack, PagerDuty)
// shows a set end user as HiddenUser, never the value, and leaves the other
// dimensions as they are (review E-82, ruling D29).
func TestOutboundHidesTheEndUser(t *testing.T) {
	d := Dimensions{Model: "gpt-5", User: "alice@customer.example", Tag: "beta", Service: "api"}
	o := d.Outbound()
	if o.User != HiddenUser || o.Model != "gpt-5" || o.Tag != "beta" || o.Service != "api" {
		t.Fatalf("Outbound = %+v", o)
	}
	if d.User != "alice@customer.example" {
		t.Fatal("Outbound must not change its receiver")
	}
	if (Dimensions{Model: "m"}).Outbound().User != "" {
		t.Fatal("an unset user stays unset")
	}
	a := SlackAlert{Event: "fired", RuleName: "r", Metric: "cost_usd", Dimensions: d}
	text := SlackText(a)
	if strings.Contains(text, "alice") || !strings.Contains(text, "user="+HiddenUser) {
		t.Errorf("slack text leaks or drops the user: %s", text)
	}
	pd, err := PagerDutyEvent("0123456789abcdef0123456789abcdef", "k", a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pd), "alice") || !strings.Contains(string(pd), HiddenUser) {
		t.Errorf("pagerduty body leaks or drops the user: %s", pd)
	}
}
