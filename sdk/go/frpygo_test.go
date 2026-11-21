package superbased

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// FR-S07: Flush is false when every span was rejected, in the quiet default.
func TestFlushFalseWhenSpansWereDropped(t *testing.T) {
	setup(t)
	st := newStub(t)
	st.reply(map[string]any{}, 401, nil)
	if _, err := Init(context.Background(), Options{Destination: DestinationLocal, Endpoint: st.URL + "/v1/traces", NodeURL: st.URL}); err != nil {
		t.Fatal(err)
	}
	_, sp := StartSpan(context.Background(), "x", SpanOptions{})
	sp.End()
	if Flush(context.Background()) {
		t.Fatal("Flush returned true while the only span was rejected with 401")
	}
	if d := GetDiagnostics(); d.DroppedSpans == 0 {
		t.Fatalf("%+v", d)
	}
}

func TestFlushTrueWhenAllExported(t *testing.T) {
	setup(t)
	memInit(t, Options{})
	_, sp := StartSpan(context.Background(), "x", SpanOptions{})
	sp.End()
	if !Flush(context.Background()) {
		t.Fatal("Flush should be true when everything exported")
	}
}

// FR-S08: no serializer or verb prints the credential or a header value.
func TestSettingsNeverSerializeTheKey(t *testing.T) {
	s, _ := resolveSettings(mapEnv(map[string]string{"SUPERBASED_API_KEY": "ik_1.topsecret"}), Options{Headers: map[string]string{"X-Token": "hdrsecret"}})
	raw, _ := json.Marshal(s)
	var sb strings.Builder
	h := slog.New(slog.NewJSONHandler(&sb, nil))
	h.Info("settings", "s", s)
	for name, out := range map[string]string{
		"json": string(raw), "%#v": fmt.Sprintf("%#v", s), "%+v": fmt.Sprintf("%+v", s), "%v": fmt.Sprintf("%v", s),
		"ptr": fmt.Sprintf("%+v", &s), "slog": sb.String(),
	} {
		if strings.Contains(out, "topsecret") || strings.Contains(out, "hdrsecret") {
			t.Errorf("%s leaks: %s", name, out)
		}
	}
	if s.APIKey == "" || s.Headers["X-Token"] == "" {
		t.Fatal("the fields themselves must stay usable in code")
	}
}

// FR-S02: FailClosed from the environment denies a degraded verdict.
func TestAdmitFailClosedFromEnv(t *testing.T) {
	setup(t)
	t.Setenv("SUPERBASED_ADMISSION_FAIL_CLOSED", "1")
	v := Admit(context.Background(), "hi", AdmitOptions{Endpoint: deadURL(t) + "/check"})
	if v.Allowed || v.Degraded == "" {
		t.Fatalf("%+v", v)
	}
}
