package alertspec

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// slackHosts are the only hosts a Slack incoming-webhook URL may name. The URL
// is admin- or owner-supplied, so restricting the host keeps the secret field
// from becoming a generic outbound URL (the generic webhook has its own field
// and its own guard).
var slackHosts = map[string]bool{
	"hooks.slack.com":     true,
	"hooks.slack-gov.com": true,
}

// ErrSlackURL is returned for a URL that is not a Slack incoming webhook. Its
// text never carries the URL (the URL is a secret).
var ErrSlackURL = errors.New("slack webhook must be an https://hooks.slack.com/ URL")

// ValidSlackWebhookURL checks a Slack incoming-webhook URL: https, one of the
// Slack hook hosts, no port, no user info, and a path under /services/ or
// /workflows/ or /triggers/. The empty string is valid (it clears the
// setting).
func ValidSlackWebhookURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || !slackHosts[strings.ToLower(u.Hostname())] {
		return ErrSlackURL
	}
	for _, p := range []string{"/services/", "/workflows/", "/triggers/"} {
		if strings.HasPrefix(u.Path, p) && len(u.Path) > len(p) {
			return nil
		}
	}
	return ErrSlackURL
}

// SlackAlert is the content-free fact set of one alert event, rendered into a
// Slack message. It carries no trace content; Dimensions may carry the end
// user the admin named on the rule (their own rule text), which no outbound
// rendering shows (Dimensions.Outbound).
type SlackAlert struct {
	// Event is "fired", "resolved" or "test".
	Event      string
	RuleName   string
	Metric     string
	Comparator string
	Threshold  float64
	Value      float64
	// Window is the human window, e.g. "7 day(s)" or "60 minute(s)".
	Window     string
	Dimensions Dimensions
	// Source names where the alert came from, e.g. the organization name or
	// "this machine".
	Source string
	// FiredAt is RFC3339.
	FiredAt string
}

// slackBody is the incoming-webhook JSON body. "text" alone renders in every
// Slack client and in a workflow trigger.
type slackBody struct {
	Text string `json:"text"`
}

// SlackPayload renders a into the JSON body for a Slack incoming webhook.
func SlackPayload(a SlackAlert) ([]byte, error) {
	b, err := json.Marshal(slackBody{Text: SlackText(a)})
	if err != nil {
		return nil, fmt.Errorf("alertspec.SlackPayload: %w", err)
	}
	return b, nil
}

// SlackText renders the message text. Slack's mrkdwn control characters
// (&, <, >) in admin text are escaped so a rule name cannot inject a link or a
// mention.
func SlackText(a SlackAlert) string {
	verb := map[string]string{"fired": "fired", "resolved": "resolved", "test": "test message"}[a.Event]
	if verb == "" {
		verb = a.Event
	}
	var b strings.Builder
	head := ":rotating_light:"
	switch a.Event {
	case "resolved":
		head = ":white_check_mark:"
	case "test":
		head = ":bell:"
	}
	fmt.Fprintf(&b, "%s *superbased alert %s*: %s\n", head, slackEscape(verb), slackEscape(a.RuleName))
	if a.Event != "test" {
		cmp := ">"
		if a.Comparator == "gte" {
			cmp = ">="
		}
		fmt.Fprintf(&b, "`%s` is %s (threshold %s %s)", slackEscape(a.Metric), formatNum(a.Value), cmp, formatNum(a.Threshold))
		if a.Window != "" {
			fmt.Fprintf(&b, " over %s", slackEscape(a.Window))
		}
		b.WriteString("\n")
	}
	// The end user shows only as set (Dimensions.Outbound; E-82).
	if pairs := a.Dimensions.Outbound().Pairs(); len(pairs) > 0 {
		parts := make([]string, 0, len(pairs))
		for _, p := range pairs {
			parts = append(parts, p[0]+"="+slackEscape(p[1]))
		}
		fmt.Fprintf(&b, "Dimensions: %s\n", strings.Join(parts, ", "))
	}
	if a.Source != "" {
		fmt.Fprintf(&b, "Source: %s\n", slackEscape(a.Source))
	}
	if a.FiredAt != "" {
		fmt.Fprintf(&b, "At: %s", slackEscape(a.FiredAt))
	}
	return strings.TrimRight(b.String(), "\n")
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func formatNum(f float64) string {
	return strconv.FormatFloat(f, 'g', 6, 64)
}
