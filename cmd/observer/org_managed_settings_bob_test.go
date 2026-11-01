package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// runEmitBobCmd runs `observer org emit-managed-settings --provider ibm-bob`
// with args into a temp --out directory and returns the policy.json object.
func runEmitBobCmd(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	dir := t.TempDir()
	cmd := newOrgEmitManagedSettingsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--provider", "ibm-bob", "--out", dir}, args...))
	if err := cmd.Execute(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	return policy, nil
}

// AP-135 decisions of 2026-10-24: EnforcedHooks by default (built by the
// per-node writer's builder), --no-enforced-hooks opts out, and
// --disable-vendor-telemetry refuses next to the OTLP export.
func TestEmitManagedSettingsIBMBobFlags(t *testing.T) {
	policy, err := runEmitBobCmd(t, "--otel-endpoint", "http://127.0.0.1:4318")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hook.IBMBobEnforcedHooks("")
	if policy["EnforcedHooks"] != want || policy["OtelConfiguration"] == nil || policy["EnableTelemetry"] != nil {
		t.Fatalf("default policy = %v", policy)
	}
	v := policy["EnforcedHooks"].(string)
	if c := hook.IBMBobEnforcedCoverage(v, hook.IBMBobHookEvents()); !c.Complete() {
		t.Fatalf("the default policy would not stand a node down: %+v", c)
	}

	policy, err = runEmitBobCmd(t, "--otel-endpoint", "http://127.0.0.1:4318", "--no-enforced-hooks")
	if err != nil || policy["EnforcedHooks"] != nil {
		t.Fatalf("--no-enforced-hooks = %v %v", policy, err)
	}

	policy, err = runEmitBobCmd(t, "--otel-endpoint", "http://127.0.0.1:4318", "--hook-binary", "/usr/local/bin/observer")
	if err != nil || !strings.Contains(policy["EnforcedHooks"].(string), "/usr/local/bin/observer hook ibm-bob") {
		t.Fatalf("--hook-binary = %v %v", policy, err)
	}

	if _, err := runEmitBobCmd(t, "--otel-endpoint", "http://127.0.0.1:4318", "--disable-vendor-telemetry"); err == nil || !strings.Contains(err.Error(), "--no-otel-config") {
		t.Fatalf("telemetry off next to the export = %v", err)
	}
	policy, err = runEmitBobCmd(t, "--disable-vendor-telemetry", "--no-otel-config")
	if err != nil || policy["EnableTelemetry"] != false || policy["OtelConfiguration"] != nil || policy["EnforcedHooks"] == nil {
		t.Fatalf("telemetry off = %v %v", policy, err)
	}
}
