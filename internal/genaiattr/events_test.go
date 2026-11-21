package genaiattr

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// eventsFile is the GenAI log-event conformance fixture (W3-7): one case per
// event table row.
type eventsFile struct {
	Cases []struct {
		Name  string                     `json:"name"`
		Event string                     `json:"event"`
		Attrs map[string]json.RawMessage `json:"attrs"`
		Body  json.RawMessage            `json:"body"`
		Want  struct {
			Bodies []struct {
				Kind string `json:"kind"`
				Raw  string `json:"raw"`
			} `json:"bodies"`
			Messages []struct {
				Kind string          `json:"kind"`
				JSON json.RawMessage `json:"json"`
			} `json:"messages"`
		} `json:"want"`
	} `json:"cases"`
}

func TestEventConformance(t *testing.T) {
	raw, err := os.ReadFile("testdata/events/genai_events.json")
	if err != nil {
		t.Fatal(err)
	}
	var f eventsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			covered[c.Event] = true
			a := Attrs{}
			for k, v := range c.Attrs {
				a[k] = toAnyValue(t, v)
			}
			var body *commonpb.AnyValue
			if len(c.Body) > 0 {
				body = toAnyValue(t, c.Body)
			}
			got := Event(c.Event, a, body)
			if len(got.Bodies) != len(c.Want.Bodies) || len(got.Messages) != len(c.Want.Messages) {
				t.Fatalf("got %d bodies %d messages, want %d %d: %+v", len(got.Bodies), len(got.Messages), len(c.Want.Bodies), len(c.Want.Messages), got)
			}
			for i, w := range c.Want.Bodies {
				if string(got.Bodies[i].Kind) != w.Kind || got.Bodies[i].Raw != w.Raw {
					t.Errorf("body %d = %s %s, want %s %s", i, got.Bodies[i].Kind, got.Bodies[i].Raw, w.Kind, w.Raw)
				}
			}
			for i, w := range c.Want.Messages {
				if string(got.Messages[i].Kind) != w.Kind || !sameJSON(t, got.Messages[i].JSON, w.JSON) {
					t.Errorf("message %d = %s %s, want %s %s", i, got.Messages[i].Kind, got.Messages[i].JSON, w.Kind, w.JSON)
				}
			}
		})
	}
	for _, r := range eventRules {
		if !covered[r.Name] {
			t.Errorf("event %s has no conformance case", r.Name)
		}
	}
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func TestEventNameAndJoin(t *testing.T) {
	a := Attrs{EventNameKey: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: EventChoice}}}
	if EventName("", a) != EventChoice || EventName(EventUserMessage, a) != EventUserMessage {
		t.Fatal("event name precedence")
	}
	if got := Event("not.a.genai.event", a, nil); len(got.Bodies)+len(got.Messages) != 0 {
		t.Fatal("an unknown event yielded content")
	}
	if got := Event(EventUserMessage, nil, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "  "}}); len(got.Messages) != 0 {
		t.Fatal("an empty body yielded a message")
	}
	if JoinMessages(nil) != "" || JoinMessages([]json.RawMessage{json.RawMessage(`{"a":1}`), json.RawMessage(`{"b":2}`)}) != `[{"a":1},{"b":2}]` {
		t.Fatal("join")
	}
	if len(EventRules()) != len(eventRules) {
		t.Fatal("EventRules copy")
	}
}
