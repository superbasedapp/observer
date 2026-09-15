package main

import (
	"strings"
	"testing"
)

// envKeys splits an env slice into the set of KEY names (text before '=').
func envKeys(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		k := kv
		v := ""
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k, v = kv[:i], kv[i+1:]
		}
		m[k] = v
	}
	return m
}

// TestScrubOOBEnv proves each OBSERVER_OOB_* channel var is removed from a
// launcher's child env while unrelated vars — and the child-legitimate
// OBSERVER_DAEMON_CHILD marker — survive. Table-driven over the OOB key set so a
// newly-added channel var that is not scrubbed fails this test loudly.
func TestScrubOOBEnv(t *testing.T) {
	survivors := []string{
		"PATH=/usr/bin",
		envDaemonChild + "=1",          // child legitimately reads this
		"OBSERVER_OOB=notarealchannel", // near-miss: no trailing key match
		"ANTHROPIC_BASE_URL=http://127.0.0.1:8820",
	}

	// Each OOB key, both `KEY=val` and bare `KEY` shapes, must be dropped.
	for _, key := range oobChildEnvKeys {
		for _, entry := range []string{key + "=secret-" + key, key} {
			in := append(append([]string{}, survivors...), entry)
			out := scrubOOBEnv(in)
			gotKeys := envKeys(out)
			if _, present := gotKeys[key]; present {
				t.Errorf("scrubOOBEnv kept %q (entry %q)", key, entry)
			}
			for _, s := range survivors {
				sk := s
				if i := strings.IndexByte(s, '='); i >= 0 {
					sk = s[:i]
				}
				if _, ok := gotKeys[sk]; !ok {
					t.Errorf("scrubOOBEnv dropped unrelated var %q (while removing %q)", sk, key)
				}
			}
		}
	}

	// Every OOB key present at once → all gone, all survivors kept, order preserved.
	in := append([]string{}, survivors...)
	for _, k := range oobChildEnvKeys {
		in = append(in, k+"=x")
	}
	out := scrubOOBEnv(in)
	if len(out) != len(survivors) {
		t.Fatalf("scrubOOBEnv len = %d, want %d (%v)", len(out), len(survivors), out)
	}
	for i, s := range survivors {
		if out[i] != s {
			t.Errorf("scrubOOBEnv reordered: out[%d]=%q want %q", i, out[i], s)
		}
	}

	// nil / empty round-trips.
	if got := scrubOOBEnv(nil); got != nil {
		t.Errorf("scrubOOBEnv(nil) = %v, want nil", got)
	}
}

// TestPrepareClaudeEnvScrubsOOB proves a real launcher site — the pure claude
// child-env builder — never forwards the trusted OOB channel vars into the
// untrusted claude child, while keeping the daemon-child marker and unrelated
// vars.
func TestPrepareClaudeEnvScrubsOOB(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin",
		envDaemonChild + "=1",
		envOOBFD + "=3",
		envOOBAuth + "=super-secret-token",
		envOOBCorr + "=nonce",
		envOOBTool + "=claude-code",
		envOOBRun + "=run-123",
	}
	out, _, err := prepareClaudeEnv(parent, "http://127.0.0.1:8820", "")
	if err != nil {
		t.Fatalf("prepareClaudeEnv: %v", err)
	}
	keys := envKeys(out)
	for _, k := range oobChildEnvKeys {
		if _, present := keys[k]; present {
			t.Errorf("prepareClaudeEnv leaked %q into the claude child env", k)
		}
	}
	if _, ok := keys[envDaemonChild]; !ok {
		t.Errorf("prepareClaudeEnv dropped %q (child legitimately reads it)", envDaemonChild)
	}
	if _, ok := keys["PATH"]; !ok {
		t.Errorf("prepareClaudeEnv dropped unrelated PATH")
	}
}
