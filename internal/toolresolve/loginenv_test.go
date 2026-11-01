package toolresolve

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestLoginEnvScript(t *testing.T) {
	got, err := LoginEnvScript([]string{"QWEN_HOME", "GROK_HOME"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{EnvMarkBegin, EnvMarkEnd, `printf 'QWEN_HOME=%s\n' "$QWEN_HOME"`, `printf 'GROK_HOME=%s\n' "$GROK_HOME"`} {
		if !strings.Contains(got, want) {
			t.Errorf("script %q lacks %q", got, want)
		}
	}
	for _, bad := range []string{"a; rm -rf /", "lower", "X$(id)", ""} {
		if _, err := LoginEnvScript([]string{bad}); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
}

func TestParseEnvMarkers(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want map[string]string
		err  error
	}{
		{"banners around the pair", "motd\n" + EnvMarkBegin + "\nQWEN_HOME=/q\nGROK_HOME=\n" + EnvMarkEnd + "\nbye", map[string]string{"QWEN_HOME": "/q", "GROK_HOME": ""}, nil},
		{"value with =", EnvMarkBegin + "\nA=/x=y\n" + EnvMarkEnd, map[string]string{"A": "/x=y"}, nil},
		{"junk line ignored", EnvMarkBegin + "\nnot a pair\nA=1\r\n" + EnvMarkEnd, map[string]string{"A": "1"}, nil},
		{"no markers", "QWEN_HOME=/q", nil, ErrNoEnvMarkers},
		{"twice", EnvMarkBegin + EnvMarkEnd + EnvMarkBegin + EnvMarkEnd, nil, ErrNoEnvMarkers},
		{"reversed", EnvMarkEnd + "\n" + EnvMarkBegin, nil, ErrNoEnvMarkers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEnvMarkers(tc.out)
			if !errors.Is(err, tc.err) || (tc.err == nil && !reflect.DeepEqual(got, tc.want)) {
				t.Errorf("ParseEnvMarkers = %v, %v; want %v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}
