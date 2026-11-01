//go:build !sbo_omit_ingest_otlp

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
)

// TestInitOTLPExport pins `observer init --otlp-export` (T-537) on a
// throwaway HOME: refused while the receiver is off, a dry run writes
// nothing, the write keeps the credential and the file's CRLF endings, a
// repeat changes nothing, an unsupported tool is named, and `--uninstall`
// (and the Remover `observer uninstall` runs) restores the original bytes.
func TestInitOTLPExport(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	cfgOff := filepath.Join(home, "off.toml")
	cfgOn := filepath.Join(home, "on.toml")
	if err := os.WriteFile(cfgOff, []byte("[observer]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgOn, []byte("[ingest.otel]\nenabled = true\nhttp_addr = \"127.0.0.1:4318\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".qwen", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "{\r\n  \"security\": {\"auth\": {\"apiKey\": \"sk-fixture-key\"}}\r\n}\r\n"
	if err := os.WriteFile(settings, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	read := func() string { b, _ := os.ReadFile(settings); return string(b) }
	var out bytes.Buffer

	if err := runOTLPExportInit(&out, cfgOff, []string{"qwen-code"}, false, false); err == nil || !strings.Contains(err.Error(), "[ingest.otel]") {
		t.Fatalf("receiver off: %v", err)
	}
	if err := runOTLPExportInit(&out, cfgOn, []string{"qwen-code"}, true, false); err != nil || read() != original {
		t.Fatalf("dry run: %v, file changed=%v", err, read() != original)
	}
	if err := runOTLPExportInit(&out, cfgOn, []string{"qwen-code"}, false, false); err != nil {
		t.Fatalf("write: %v\n%s", err, out.String())
	}
	got := read()
	if !strings.Contains(got, "sk-fixture-key") || !strings.Contains(got, "otlpEndpoint") || strings.Count(got, "\n") != strings.Count(got, "\r\n") {
		t.Fatalf("written file:\n%q", got)
	}
	if strings.Contains(out.String(), "sk-fixture-key") {
		t.Fatal("init printed a value from the credential file")
	}
	if err := runOTLPExportInit(&out, cfgOn, []string{"qwen-code"}, false, false); err != nil || read() != got {
		t.Fatalf("repeat: %v", err)
	}
	out.Reset()
	if err := runOTLPExportInit(&out, cfgOn, []string{"cursor"}, false, false); err == nil || !strings.Contains(out.String(), "no exporter writer") {
		t.Fatalf("cursor: %v %s", err, out.String())
	}

	// The uninstall seam removes it.
	rem, err := clientwire.NewRemover(clientwire.RemoveOptions{BinaryPath: "/opt/observer", Getenv: os.Getenv})
	if err != nil {
		t.Fatal(err)
	}
	m := rem.Remove("qwen-code", clientwire.PartTelemetry)
	if m.Telemetry == nil || !m.Telemetry.Changed || m.Failed() || read() != original {
		t.Fatalf("uninstall removal: %+v, restored=%v", m.Telemetry, read() == original)
	}
	// And init --uninstall is a no-op on a clean file.
	if err := runOTLPExportInit(&out, cfgOn, []string{"qwen-code"}, false, true); err != nil || read() != original {
		t.Fatalf("init --uninstall on a clean file: %v", err)
	}
}
