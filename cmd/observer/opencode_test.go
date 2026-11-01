package main

import (
	"strings"
	"testing"
)

func TestPrepareOpencodeEnv(t *testing.T) {
	t.Run("injects OPENAI_BASE_URL with /v1 when unset", func(t *testing.T) {
		env, baseURL, preset := prepareOpencodeEnv(
			[]string{"PATH=/bin", "HOME=/home/dev"},
			"http://127.0.0.1:8820",
		)
		if preset {
			t.Fatal("expected preset=false")
		}
		if baseURL != "http://127.0.0.1:8820/v1" {
			t.Errorf("baseURL = %q", baseURL)
		}
		if !containsKV(env, "OPENAI_BASE_URL=http://127.0.0.1:8820/v1") {
			t.Errorf("env missing injected OPENAI_BASE_URL: %v", env)
		}
	})

	t.Run("trailing slash on proxy URL is not doubled", func(t *testing.T) {
		_, baseURL, _ := prepareOpencodeEnv(nil, "http://127.0.0.1:8820/")
		if baseURL != "http://127.0.0.1:8820/v1" {
			t.Errorf("baseURL = %q (want no //v1)", baseURL)
		}
	})

	t.Run("user's existing OPENAI_BASE_URL wins", func(t *testing.T) {
		env, baseURL, preset := prepareOpencodeEnv(
			[]string{"OPENAI_BASE_URL=https://my.proxy/v1", "PATH=/bin"},
			"http://127.0.0.1:8820",
		)
		if !preset {
			t.Fatal("expected preset=true")
		}
		if baseURL != "https://my.proxy/v1" {
			t.Errorf("baseURL = %q (should keep user's)", baseURL)
		}
		// must not append a second OPENAI_BASE_URL
		if n := countKey(env, "OPENAI_BASE_URL"); n != 1 {
			t.Errorf("OPENAI_BASE_URL appears %d times, want 1", n)
		}
	})

	t.Run("empty existing value is treated as unset", func(t *testing.T) {
		_, _, preset := prepareOpencodeEnv([]string{"OPENAI_BASE_URL="}, "http://127.0.0.1:8820")
		if preset {
			t.Error("empty OPENAI_BASE_URL should not count as preset")
		}
	})
}

func containsKV(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func countKey(env []string, key string) int {
	n := 0
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i > 0 && e[:i] == key {
			n++
		}
	}
	return n
}

// TestPrepareOpencodeZenRoute pins the OpenCode Zen route: the built-in
// "opencode" provider is pointed at the proxy's opencode-zen lane, and a
// caller's own OPENCODE_CONFIG_CONTENT is never overwritten.
func TestPrepareOpencodeZenRoute(t *testing.T) {
	env, routed := prepareOpencodeZenRoute([]string{"PATH=/bin"}, "http://127.0.0.1:8820/", "")
	if !routed {
		t.Fatal("want routed")
	}
	got := envValue(env, "OPENCODE_CONFIG_CONTENT")
	want := `{"provider":{"opencode":{"options":{"baseURL":"http://127.0.0.1:8820/up/opencode-zen/v1"}}}}`
	if got != want {
		t.Fatalf("OPENCODE_CONFIG_CONTENT = %s, want %s", got, want)
	}
	// CLI-2: the launcher's own OPENAI_BASE_URL rides in the config content
	// too, so a project opencode.json's provider.openai.options.baseURL
	// (which outranks the environment variable) cannot take it away.
	env, routed = prepareOpencodeZenRoute([]string{"PATH=/bin"}, "http://127.0.0.1:8820/", "http://127.0.0.1:8820/v1")
	got = envValue(env, "OPENCODE_CONFIG_CONTENT")
	want = `{"provider":{"openai":{"options":{"baseURL":"http://127.0.0.1:8820/v1"}},"opencode":{"options":{"baseURL":"http://127.0.0.1:8820/up/opencode-zen/v1"}}}}`
	if !routed || got != want {
		t.Fatalf("OPENCODE_CONFIG_CONTENT = %s, want %s", got, want)
	}
	mine := `{"provider":{"openrouter":{}}}`
	env, routed = prepareOpencodeZenRoute([]string{"OPENCODE_CONFIG_CONTENT=" + mine}, "http://127.0.0.1:8820", "http://127.0.0.1:8820/v1")
	if routed || envValue(env, "OPENCODE_CONFIG_CONTENT") != mine {
		t.Fatalf("caller config overwritten: routed=%v env=%v", routed, env)
	}
}

// TestOpencodeContentShadowsRoute pins CLI-2's read of a caller-set
// OPENCODE_CONFIG_CONTENT (environment only): one case per outcome. On the
// old code such a launch printed "routing via" and kept the route proof.
func TestOpencodeContentShadowsRoute(t *testing.T) {
	const proxy = "http://127.0.0.1:8820"
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"unset", "", false},
		{"another provider only", `{"provider":{"openrouter":{}}}`, false},
		{"openai at the proxy", `{"provider":{"openai":{"options":{"baseURL":"http://127.0.0.1:8820/v1"}}}}`, false},
		{"openai elsewhere", `{"provider":{"openai":{"options":{"baseURL":"https://api.openai.com/v1"}}}}`, true},
		{"does not parse", `{"provider":`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var env []string
			if tc.content != "" {
				env = []string{"OPENCODE_CONFIG_CONTENT=" + tc.content}
			}
			if got := opencodeContentShadowsRoute(env, proxy); got != tc.want {
				t.Fatalf("shadows = %v, want %v", got, tc.want)
			}
		})
	}
}
