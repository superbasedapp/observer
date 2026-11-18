//go:build !sbo_omit_ingest_otlp

package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/configschema"
)

// TestSetupTelemetryStep pins T-537's dashboard step on a throwaway home: the
// preview writes nothing, the write points qwen-code's exporter at the
// node while keeping the provider key byte-for-byte, a repeat is a no-op,
// and the removal restores the original file exactly. With the receiver off
// the write is refused with the setting that fixes it.
func TestSetupTelemetryStep(t *testing.T) {
	server, home := wizardTestServer(t)
	settings := filepath.Join(home, ".qwen", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	original := "{\r\n  \"security\": {\"auth\": {\"apiKey\": \"sk-fixture-key\"}}\r\n}\r\n"
	if err := os.WriteFile(settings, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// Receiver off: refused, file untouched.
	if rr := wizardRemovePost(server, "/api/setup/telemetry", `{"tool":"qwen-code","dry_run":true}`); rr.Code != 412 || !strings.Contains(rr.Body.String(), "[ingest.otel]") ||
		!strings.Contains(rr.Body.String(), telemetryReceiverSettingsLink) {
		t.Fatalf("receiver off: %d %s", rr.Code, rr.Body.String())
	}

	if err := os.WriteFile(server.opts.ConfigPath, []byte("[ingest.otel]\nenabled = true\nhttp_addr = \"127.0.0.1:4318\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	type reply struct {
		Changed, Wired, AlreadySet bool
		Summary                    []string
		Error                      string
	}
	post := func(body string) reply {
		t.Helper()
		rr := wizardRemovePost(server, "/api/setup/telemetry", body)
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", body, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "sk-fixture-key") {
			t.Fatal("the reply carried a value from the credential file")
		}
		var r struct {
			Changed    bool     `json:"changed"`
			Wired      bool     `json:"wired"`
			AlreadySet bool     `json:"already_set"`
			Summary    []string `json:"summary"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return reply{Changed: r.Changed, Wired: r.Wired, AlreadySet: r.AlreadySet, Summary: r.Summary}
	}
	read := func() string {
		b, _ := os.ReadFile(settings)
		return string(b)
	}

	if r := post(`{"tool":"qwen-code","dry_run":true}`); !r.Changed || len(r.Summary) == 0 || read() != original {
		t.Fatalf("preview: %+v, file changed=%v", r, read() != original)
	}
	if r := post(`{"tool":"qwen-code"}`); !r.Changed || !r.Wired {
		t.Fatalf("write: %+v", r)
	}
	got := read()
	if !strings.Contains(got, "sk-fixture-key") || !strings.Contains(got, `"otlpEndpoint": "http://127.0.0.1:4318"`) {
		t.Fatalf("written file:\n%s", got)
	}
	// Windows has no POSIX permission bits (os.Stat reports 0666 or 0444
	// there), so "0600 kept" is only observable on a POSIX host.
	if info, _ := os.Stat(settings); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600 kept", info.Mode().Perm())
	}
	if r := post(`{"tool":"qwen-code"}`); r.Changed || !r.AlreadySet {
		t.Fatalf("repeat: %+v", r)
	}
	if r := post(`{"tool":"qwen-code","undo":true}`); !r.Changed || r.Wired {
		t.Fatalf("remove: %+v", r)
	}
	if read() != original {
		t.Fatalf("remove did not restore the original bytes:\n%q", read())
	}
	// A tool with no exporter writer is not offered.
	if rr := wizardRemovePost(server, "/api/setup/telemetry", `{"tool":"cursor","dry_run":true}`); rr.Code != 400 {
		t.Fatalf("cursor: %d", rr.Code)
	}
}

// TestSetupTelemetryReceiverPosture pins P3-12 and P3-20 on a throwaway home,
// one row per receiver posture: a receiver that requires its edge token is
// refused with the Settings place that fixes it (and no file is touched, so
// no token can land in a vendor file); a wildcard bind is written as the
// loopback endpoint and removed again by its ownership record; a user's own
// loopback collector is a conflict and survives an undo.
func TestSetupTelemetryReceiverPosture(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cfg        string
		initial    string
		wantStatus int
		wantInFile string
		wantLink   bool
	}{
		{
			name:       "token required: refused",
			cfg:        "[ingest.otel]\nenabled = true\nhttp_addr = \"0.0.0.0:4318\"\nallow_non_loopback = true\n",
			initial:    "{\n  \"theme\": \"dark\"\n}\n",
			wantStatus: 412,
			wantLink:   true,
		},
		{
			name:       "wildcard bind: loopback endpoint",
			cfg:        "[ingest.otel]\nenabled = true\nhttp_addr = \"0.0.0.0:4318\"\n",
			initial:    "{\n  \"theme\": \"dark\"\n}\n",
			wantStatus: 200,
			wantInFile: `"otlpEndpoint": "http://127.0.0.1:4318"`,
		},
		{
			name:       "user loopback collector: conflict",
			cfg:        "[ingest.otel]\nenabled = true\nhttp_addr = \"127.0.0.1:4318\"\n",
			initial:    `{"telemetry": {"enabled": true, "target": "local", "otlpEndpoint": "http://127.0.0.1:4317", "otlpProtocol": "http"}}` + "\n",
			wantStatus: 409,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, home := wizardTestServer(t)
			settings := filepath.Join(home, ".qwen", "settings.json")
			if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settings, []byte(tc.initial), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(server.opts.ConfigPath, []byte(tc.cfg), 0o644); err != nil {
				t.Fatal(err)
			}
			rr := wizardRemovePost(server, "/api/setup/telemetry", `{"tool":"qwen-code"}`)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantLink != strings.Contains(rr.Body.String(), telemetryReceiverSettingsLink) {
				t.Fatalf("settings link presence = %v, want %v: %s", !tc.wantLink, tc.wantLink, rr.Body.String())
			}
			got, _ := os.ReadFile(settings)
			if tc.wantInFile == "" {
				if string(got) != tc.initial {
					t.Fatalf("file changed on a refusal:\n%s", got)
				}
			} else if !strings.Contains(string(got), tc.wantInFile) || strings.Contains(string(got), "0.0.0.0") {
				t.Fatalf("written file:\n%s", got)
			}
			// An undo removes only what Observer recorded installing.
			if rr := wizardRemovePost(server, "/api/setup/telemetry", `{"tool":"qwen-code","undo":true}`); rr.Code != 200 {
				t.Fatalf("undo: %d %s", rr.Code, rr.Body.String())
			}
			after, _ := os.ReadFile(settings)
			if string(after) != tc.initial {
				t.Fatalf("undo left:\n%s\nwant:\n%s", after, tc.initial)
			}
		})
	}
}

// TestTelemetryReceiverKeysLiveInTheLinkedSection pins that the Settings
// section the refusal links to really edits the receiver keys (P3-20: no
// config.toml dead end).
func TestTelemetryReceiverKeysLiveInTheLinkedSection(t *testing.T) {
	for _, key := range []string{"ingest.otel.enabled", "ingest.otel.http_addr", "ingest.otel.allow_non_loopback"} {
		sec, ok := configschema.SectionOf(key)
		if !ok || "/settings?section="+sec != telemetryReceiverSettingsLink {
			t.Errorf("%s is in section %q (ok=%v); the refusal links %s", key, sec, ok, telemetryReceiverSettingsLink)
		}
	}
}

// TestTelemetryRefusalLinkIsTheTableRow: the receiver refusal's deep link
// fields come from the one settingslink table and agree with its older
// settings_link field.
func TestTelemetryRefusalLinkIsTheTableRow(t *testing.T) {
	f := otelExportFields()
	if f.Settings != telemetryReceiverSettingsLink || f.SettingsLabel != "Settings > OTel export" {
		t.Fatalf("otel export fields = %+v, want %s", f, telemetryReceiverSettingsLink)
	}
}
