package main

import (
	"strings"
	"testing"
)

func TestParseFlags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		args      []string
		wantErr   string
		wantAgent string
		wantForb  int
	}{
		{name: "release", args: []string{"-out", "x", "-version", "v1.31.0", "-released", "2026-08-17"}, wantAgent: "1.31.0"},
		{name: "main with dev agent", args: []string{"-out", "x", "-version", "main", "-agent-version", "dev", "-released", "2026-11-12"}, wantAgent: "dev"},
		{name: "short forbid values are dropped", args: []string{"-out", "x", "-version", "v1.38.0", "-released", "2026-11-09", "-forbid", "ab", "-forbid", "host-01"}, wantAgent: "1.38.0", wantForb: 1},
		{name: "missing out", args: []string{"-version", "v1.31.0", "-released", "2026-08-17"}, wantErr: "-out is required"},
		{name: "bad version", args: []string{"-out", "x", "-version", "1.31", "-released", "2026-08-17"}, wantErr: "-version"},
		{name: "bad date", args: []string{"-out", "x", "-version", "v1.31.0", "-released", "2026-13-40"}, wantErr: "-released"},
		{name: "stray argument", args: []string{"-out", "x", "-version", "v1.31.0", "-released", "2026-08-17", "extra"}, wantErr: "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o, err := parseFlags(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.agentVersion != tc.wantAgent || len(o.forbid) != tc.wantForb {
				t.Errorf("agent %q forbid %d, want %q %d", o.agentVersion, len(o.forbid), tc.wantAgent, tc.wantForb)
			}
		})
	}
}

func TestCheckEnvelope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		forbid  []string
		wantErr string
	}{
		{name: "clean", body: `{"agent_version":"1.31.0","sessions":[]}`},
		{name: "not json", body: `nope`, wantErr: "not a JSON envelope"},
		{name: "wrong agent version", body: `{"agent_version":"1.30.0"}`, wantErr: "agent_version"},
		{name: "host name", body: `{"agent_version":"1.31.0","x":"BUILD-HOST-7"}`, forbid: []string{"build-host-7"}, wantErr: "-forbid value #1"},
		{name: "escaped windows path", body: `{"agent_version":"1.31.0","x":"C:\\Users\\someone\\x"}`, forbid: []string{`C:\Users\someone`}, wantErr: "escaped"},
		{name: "env name", body: `{"agent_version":"1.31.0","env":["LOCALAPPDATA=x"]}`, wantErr: "environment name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := checkEnvelope([]byte(tc.body), "1.31.0", tc.forbid)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(string(out), "\n") || !strings.Contains(string(out), "\n  \"sessions\"") {
				t.Errorf("not indented: %q", out)
			}
		})
	}
}
