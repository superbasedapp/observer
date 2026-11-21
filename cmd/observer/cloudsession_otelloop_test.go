package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// TestOTelLoopEnsure pins the ensure decision of the in-sandbox loopback
// receiver (lane CA-C7): nothing happens outside the agent's cloud sandbox;
// a receiver already answering is left alone; otherwise one is spawned and
// awaited; bad input and spawn failures are reported, never fatal.
func TestOTelLoopEnsure(t *testing.T) {
	cloud := func(name string) (string, bool) {
		if name == "CLAUDE_CODE_REMOTE" {
			return "true", true
		}
		return "", false
	}
	local := func(string) (string, bool) { return "", false }
	tests := []struct {
		name      string
		agent     string
		addr      string
		env       cloudsession.LookupEnv
		upBefore  bool
		upAfter   bool
		spawnErr  error
		want      otelLoopEnsureState
		wantSpawn int
	}{
		{"not in the cloud", "claude-code", "127.0.0.1:4318", local, false, true, nil, otelLoopNotCloud, 0},
		{"already running", "claude-code", "127.0.0.1:4318", cloud, true, true, nil, otelLoopRunning, 0},
		{"started", "claude-code", "127.0.0.1:4318", cloud, false, true, nil, otelLoopStarted, 1},
		{"spawn failed", "claude-code", "127.0.0.1:4318", cloud, false, false, errors.New("boom"), otelLoopSpawnFailed, 1},
		{"never answers", "claude-code", "127.0.0.1:4318", cloud, false, false, nil, otelLoopNoAnswer, 1},
		{"non-loopback address", "claude-code", "10.0.0.1:4318", cloud, false, true, nil, otelLoopBadInput, 0},
		{"agent without a loopback route", "copilot", "127.0.0.1:4318", cloud, false, true, nil, otelLoopBadInput, 0},
		{"unknown agent", "nope", "127.0.0.1:4318", cloud, false, true, nil, otelLoopBadInput, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spawned := 0
			up := tc.upBefore
			r := runOTelLoopEnsure(otelLoopEnsureInput{
				Agent: tc.agent, Addr: tc.addr, Env: tc.env, Wait: 150 * time.Millisecond,
				Probe: func(string) bool { return up },
				Spawn: func(string) error {
					spawned++
					if tc.spawnErr != nil {
						return tc.spawnErr
					}
					up = tc.upAfter
					return nil
				},
			})
			if r.State != tc.want || spawned != tc.wantSpawn {
				t.Fatalf("state = %s (err %v), spawned %d; want %s, %d", r.State, r.Err, spawned, tc.want, tc.wantSpawn)
			}
		})
	}
}

// TestApplyOTelLoopbackOff: without the flag the init plan is returned
// untouched, so `cloud-session init` writes byte-identical files.
func TestApplyOTelLoopbackOff(t *testing.T) {
	plan := cloudsession.RepoPlan{Manual: []string{"x"}, Changes: []cloudsession.FileChange{{Path: cloudsession.ClaudeSettingsPath, After: "{}\n"}}}
	got, err := applyOTelLoopback(plan, cloudsession.PlanOptions{}, false, "")
	if err != nil || len(got.Manual) != 1 || got.Changes[0].After != "{}\n" {
		t.Fatalf("off plan changed: %+v, %v", got, err)
	}
}

// TestOTelLoopServeEnv pins the minimal environment ensure starts the
// detached receiver with (ledger CLOUDTEL-3): home, config and database
// locations, the non-secret OBSERVER_ overrides and the agent's cloud marker
// variables pass; the ship token, provider keys and every other variable do
// not.
func TestOTelLoopServeEnv(t *testing.T) {
	a, err := cloudsession.AgentByID("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	markers := cloudsession.MarkerEnvNames(a)
	cases := []struct {
		kv   string
		keep bool
	}{
		{"HOME=/root", true},
		{"PATH=/usr/bin", true},
		{"TMPDIR=/tmp", true},
		{"XDG_CONFIG_HOME=/root/.config", true},
		{`SystemRoot=C:\Windows`, true},
		{"OBSERVER_OBSERVER_DB_PATH=/data/observer.db", true},
		{"OBSERVER_INGEST_OTEL_CONTENT_CAPTURE=true", true},
		{"CLAUDE_CODE_REMOTE=true", true},
		{"CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE=cloud_default", true},
		{"CLAUDE_CODE_REMOTE_SESSION_ID=cse_abc", true},
		{"SBO_CLOUD_SESSION_TOKEN=sbo_ship_secret", false},
		{"SBO_CLOUD_SESSION_URL=https://node.example.com", false},
		{"SBO_CLOUD_SESSION_TOKEN_FILE=/run/token", false},
		{"ANTHROPIC_API_KEY=sk-ant-x", false},
		{"GITHUB_TOKEN=ghs_x", false},
		{"AWS_SECRET_ACCESS_KEY=x", false},
		{"OBSERVER_CI_CREDENTIAL=x", false},
		{"OBSERVER_ORG_CLIENT_TOKEN=x", false},
		{"OBSERVER_SOME_API_KEY=x", false},
		{`=C:=C:\work`, false},
		{"NOEQUALS", false},
	}
	var environ []string
	for _, tc := range cases {
		environ = append(environ, tc.kv)
	}
	got := map[string]bool{}
	for _, kv := range otelLoopServeEnv(environ, markers) {
		got[kv] = true
	}
	for _, tc := range cases {
		if got[tc.kv] != tc.keep {
			t.Errorf("%q: kept=%v, want %v", tc.kv, got[tc.kv], tc.keep)
		}
	}
	// Without the agent's markers (an unknown --agent) the marker variables
	// are dropped too.
	for _, kv := range otelLoopServeEnv([]string{"CLAUDE_CODE_REMOTE=true", "HOME=/root"}, nil) {
		if kv == "CLAUDE_CODE_REMOTE=true" {
			t.Errorf("marker variable kept with no markers")
		}
	}
}

// TestOTelLoopRefusedWhileIngestOTLPInactive pins the component gate of the
// in-sandbox receiver: with ingest.otlp removed, both `ensure` and `serve`
// print the refusal line before binding or spawning anything; serve exits 3
// and ensure, which a non-gate hook runs, exits 0.
func TestOTelLoopRefusedWhileIngestOTLPInactive(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[components]\nremove = [\""+otelLoopComponent+"\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args     []string
		wantExit int // 0: the hook-run ensure never fails its hook
	}{
		{[]string{"serve", "--addr", "127.0.0.1:4399", "--config", cfgPath}, componentstate.RefusalExitCode},
		{[]string{"ensure", "--agent", "claude-code", "--config", cfgPath}, 0},
	} {
		args := tc.args
		cmd := newCloudSessionOTelReceiverCmd()
		var stderr bytes.Buffer
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&stderr)
		cmd.SetArgs(args)
		err := cmd.Execute()
		if tc.wantExit == 0 {
			if err != nil {
				t.Fatalf("%s: err = %v, want nil (exit 0)", args[0], err)
			}
		} else {
			var code exitErr
			if !errors.As(err, &code) || int(code) != tc.wantExit {
				t.Fatalf("%s: err = %v, want exit %d", args[0], err, tc.wantExit)
			}
		}
		if !strings.Contains(stderr.String(), otelLoopComponent) {
			t.Errorf("%s: refusal line %q does not name %s", args[0], stderr.String(), otelLoopComponent)
		}
	}
	// No [components] block: the gate follows this build's default set. A
	// plain build activates every compiled component, so a legacy install
	// passes; a published edition starts from its own default set, which
	// may leave ingest.otlp inactive (the developer edition does), and then
	// the gate refuses, as it should.
	absent := filepath.Join(t.TempDir(), "absent.toml")
	err := otelLoopRefused(newCloudSessionOTelReceiverCmd(), absent)
	if defaultActive(otelLoopComponent) {
		if err != nil {
			t.Fatalf("legacy install refused: %v", err)
		}
	} else {
		var code exitErr
		if !errors.As(err, &code) || int(code) != componentstate.RefusalExitCode {
			t.Fatalf("unconfigured install, %s inactive by default in this build (distro %q): err = %v, want exit %d",
				otelLoopComponent, components.BuildDistro(), err, componentstate.RefusalExitCode)
		}
	}
	// Selected where the edition leaves it off: the gate lets the command
	// through in every build that offers ingest.otlp.
	if !slices.Contains(components.Compiled(components.BinaryNode), otelLoopComponent) {
		return
	}
	selected := filepath.Join(t.TempDir(), "selected.toml")
	if err := os.WriteFile(selected, []byte(selectionTOMLIfInactive(t, otelLoopComponent)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := otelLoopRefused(newCloudSessionOTelReceiverCmd(), selected); err != nil {
		t.Fatalf("active %s refused: %v", otelLoopComponent, err)
	}
}
