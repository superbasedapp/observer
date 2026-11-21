package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeSettings struct {
	got SetSettingRequest
	q   SettingsQuery
}

func (f *fakeSettings) GetSettings(_ context.Context, q SettingsQuery) (any, error) {
	f.q = q
	return map[string]any{"ok": true}, nil
}

func (f *fakeSettings) SetSetting(_ context.Context, r SetSettingRequest) (SetSettingResult, error) {
	f.got = r
	return SetSettingResult{Status: "proposed", Key: r.Key, Proposal: 7}, nil
}

func TestSettingsToolsRelayToTheBackend(t *testing.T) {
	f := &fakeSettings{}
	set := &setSettingTool{b: f, client: func() string { return "claude-code" }}
	cases := []struct {
		args, want string
	}{
		{`{"key":"a.b","value":"online"}`, "online"},
		{`{"key":"a.b","value":true}`, "true"},
		{`{"key":"a.b","value":0.5}`, "0.5"},
		{`{"key":"a.b","value":["x","y"]}`, "x,y"},
	}
	for _, c := range cases {
		if _, err := set.Invoke(context.Background(), json.RawMessage(c.args)); err != nil {
			t.Fatalf("%s: %v", c.args, err)
		}
		if f.got.Value != c.want || f.got.Client != "claude-code" {
			t.Fatalf("%s: backend got %+v, want value %q", c.args, f.got, c.want)
		}
	}
	for _, bad := range []string{`{"key":"a.b"}`, `{"value":"x"}`, `{"key":"a.b","value":{"x":1}}`} {
		if _, err := set.Invoke(context.Background(), json.RawMessage(bad)); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
	get := &getSettingsTool{b: f}
	if _, err := get.Invoke(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("get_settings with no filter is refused (500+ keys)")
	}
	if _, err := get.Invoke(context.Background(), json.RawMessage(`{"prefix":" observability "}`)); err != nil || f.q.Prefix != "observability" {
		t.Fatalf("get_settings prefix: %+v %v", f.q, err)
	}
}

func TestSettingsToolsAnswerHonestlyWhenUnwired(t *testing.T) {
	for _, tool := range []Tool{&getSettingsTool{}, &setSettingTool{}} {
		_, err := tool.Invoke(context.Background(), json.RawMessage(`{"key":"a","value":"b"}`))
		if !errors.Is(err, errSettingsUnwired) || !strings.Contains(err.Error(), "observer config") {
			t.Fatalf("%s unwired: %v", tool.Name(), err)
		}
	}
}
