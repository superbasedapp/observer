package diag

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func joined(c Check) string { return c.Message + " | " + strings.Join(c.Details, " | ") }

func TestCortexTeamsAbsentIsInformational(t *testing.T) {
	c := checkCortexTeamsAt(config.Config{}, []string{filepath.Join(t.TempDir(), "missing.json")})
	if c.Status != StatusOK || !strings.Contains(c.Message, "--provider cortex-code") {
		t.Fatalf("absent = %+v", c)
	}
}

func TestCortexTeamsValidatesTheFile(t *testing.T) {
	dir := t.TempDir()
	mcp := filepath.Join(dir, "mcp.json")
	writeFile(t, mcp, `{"mcpServers":{}}`, 0o644)
	for _, tc := range []struct {
		name, body string
		mode       os.FileMode
		wantWarn   string
	}{
		{"bad_json", `{`, 0o644, "not valid JSON"},
		{"no_version", `{"files":{}}`, 0o644, `"version": "1.0"`},
		{"missing_mcp_file", `{"version":"1.0","files":{"mcpFile":"` + filepath.ToSlash(filepath.Join(dir, "nope.json")) + `"}}`, 0o644, "is missing"},
		{"group_writable", `{"version":"1.0"}`, 0o666, "writable by group or others"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "group_writable" && runtime.GOOS == "windows" {
				t.Skip("mode bits are not inspected on Windows")
			}
			p := filepath.Join(dir, tc.name+".json")
			writeFile(t, p, tc.body, tc.mode)
			c := checkCortexTeamsAt(config.Config{}, []string{p})
			if c.Status != StatusWarn || !strings.Contains(joined(c), tc.wantWarn) {
				t.Fatalf("%s: %+v", tc.name, c)
			}
		})
	}
	good := filepath.Join(dir, "good.json")
	writeFile(t, good, `{"version":"1.0","files":{"mcpFile":"`+filepath.ToSlash(mcp)+`"}}`, 0o644)
	c := checkCortexTeamsAt(config.Config{}, []string{good})
	if !strings.Contains(joined(c), "present and parseable") || !strings.Contains(joined(c), "files.mcpFile present") {
		t.Fatalf("good file: %+v", c)
	}
}

func TestIBMBobTeamsValidatesThePolicy(t *testing.T) {
	dir := t.TempDir()
	if c := checkIBMBobTeamsAt(config.Config{}, nil, ""); c.Status != StatusOK || !strings.Contains(c.Message, "--provider ibm-bob") {
		t.Fatalf("absent = %+v", c)
	}
	off := config.Config{}
	for _, tc := range []struct {
		name, body, wantWarn string
	}{
		{"not_object", `[1]`, "not a JSON object"},
		{"not_string", `{"OtelConfiguration":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:4318"}}`, "not a string"},
		{"no_endpoint", `{"OtelConfiguration":"{\"OTEL_SERVICE_NAME\":\"IBM Bob\"}"}`, "no valid OTEL_EXPORTER_OTLP_ENDPOINT"},
		{"receiver_off", `{"OtelConfiguration":"{\"OTEL_EXPORTER_OTLP_ENDPOINT\":\"http://127.0.0.1:4318\"}"}`, "[ingest.otel].enabled is false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".json")
			writeFile(t, p, tc.body, 0o644)
			c := checkIBMBobTeamsAt(off, []string{p}, "")
			if c.Status != StatusWarn || !strings.Contains(joined(c), tc.wantWarn) {
				t.Fatalf("%s: %+v", tc.name, c)
			}
		})
	}
	// Receiver enabled but nothing listening on the (closed) port: WARN, never FAIL.
	on := config.Config{}
	on.Ingest.OTel.Enabled = true
	p := filepath.Join(dir, "unreachable.json")
	writeFile(t, p, `{"OtelConfiguration":"{\"OTEL_EXPORTER_OTLP_ENDPOINT\":\"http://127.0.0.1:1\"}"}`, 0o644)
	if c := checkIBMBobTeamsAt(on, []string{p}, ""); c.Status != StatusWarn || !strings.Contains(joined(c), "NOT reachable") {
		t.Fatalf("unreachable: %+v", c)
	}
}

// AP-135 decisions of 2026-10-24: the doctor reports whether EnforcedHooks
// carries Observer's Bob hooks and whether the per-node registration stood
// down, and flags EnableTelemetry=false next to the OTLP export.
func TestIBMBobTeamsEnforcedHooks(t *testing.T) {
	// A runnable observer at an absolute path, so the binary check is
	// deterministic whatever this host's PATH holds.
	bin := filepath.Join(t.TempDir(), "observer")
	writeFile(t, bin, "#!/bin/sh\n", 0o755)
	full, err := hook.IBMBobEnforcedHooks(bin)
	if err != nil {
		t.Fatal(err)
	}
	missingBin, _ := hook.IBMBobEnforcedHooks(filepath.Join(t.TempDir(), "gone", "observer"))
	partial := `{"PreToolUse":[{"hooks":[{"type":"command","command":"observer hook ibm-bob PreToolUse"}]}]}`
	broken := `{"Notification":[]}`
	off := false
	pol := func(v *string) hook.IBMBobPolicy {
		return hook.IBMBobPolicy{Source: `HKLM\SOFTWARE\Policies\IBM\Bob`, Found: true, EnforcedHooks: v}
	}
	empty := t.TempDir()
	withEntries := t.TempDir()
	reg, err := hook.NewRegistry(hook.Options{
		BinaryPath: "/opt/observer", HomeDir: withEntries,
		ChecksumsPath: filepath.Join(withEntries, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("ibm-bob"); res.Error != nil {
		t.Fatal(res.Error)
	}
	for _, tc := range []struct {
		name   string
		pol    hook.IBMBobPolicy
		home   string
		status Status
		want   string
	}{
		{"absent", hook.IBMBobPolicy{}, empty, StatusOK, "not deployed"},
		{"stood_down", pol(&full), empty, StatusOK, "stood down"},
		{"binary_missing", pol(&missingBin), empty, StatusWarn, "does not resolve"},
		{"leftover_entries", pol(&full), withEntries, StatusWarn, "fire twice"},
		{"partial", pol(&partial), empty, StatusWarn, "but not UserPromptSubmit"},
		{"broken", pol(&broken), empty, StatusWarn, "not relied on"},
		{"no_hooks", hook.IBMBobPolicy{Source: "x", Found: true, OtelExport: true}, empty, StatusOK, "no EnforcedHooks"},
		{"telemetry_kills_export", hook.IBMBobPolicy{Source: "x", Found: true, OtelExport: true, EnableTelemetry: &off}, empty, StatusWarn, "silenced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := checkIBMBobTeamsPolicy(config.Config{}, tc.pol, hook.IBMBobPolicyDomains{}, tc.home)
			if c.Status != tc.status || !strings.Contains(joined(c), tc.want) {
				t.Fatalf("%+v", c)
			}
		})
	}

	// The Linux file flow reads EnforcedHooks from the same document.
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	body, _ := json.Marshal(map[string]string{"EnforcedHooks": full})
	writeFile(t, p, string(body), 0o644)
	c := checkIBMBobTeamsAt(config.Config{}, []string{p}, empty)
	if !strings.Contains(joined(c), "EnforcedHooks") {
		t.Fatalf("file flow = %+v", c)
	}
}
