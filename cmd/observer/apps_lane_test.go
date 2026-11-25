package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestAppsLaneAddListRemove pins `observer apps lane add|list|remove`: the
// lane lands in [proxy.upstreams] (and its models in [proxy.app_lanes]),
// the client base URL is printed, a duplicate or a bad id is refused, and
// remove takes both away.
func TestAppsLaneAddListRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("# my config\n[proxy]\nport = 8820\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := newAppsLaneCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append(args, "--config", path))
		err := cmd.Execute()
		return out.String(), err
	}
	out, err := run("add", "openai", "--models", "gpt-5-nano, gpt-5-mini")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "http://127.0.0.1:8820/up/openai/v1") {
		t.Fatalf("add did not print the client base URL:\n%s", out)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Upstreams["openai"] != "https://api.openai.com" || len(cfg.Proxy.AppLanes.Models["openai"]) != 2 {
		t.Fatalf("written config: upstreams=%v models=%v", cfg.Proxy.Upstreams, cfg.Proxy.AppLanes.Models)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "# my config") {
		t.Fatalf("the edit lost the file's comment:\n%s", raw)
	}
	if _, err := run("add", "openai"); err == nil {
		t.Fatal("a duplicate add must be refused")
	}
	if _, err := run("add", "Bad Id"); err == nil {
		t.Fatal("a bad id must be refused")
	}
	if _, err := run("add", "mine"); err == nil {
		t.Fatal("an unknown id with no --upstream must be refused")
	}
	if _, err := run("add", "mine", "--upstream", "http://example.com"); err == nil {
		t.Fatal("plain http to a non-loopback host must be refused")
	}
	if out, err := run("add", "local", "--upstream", "http://127.0.0.1:11434/"); err != nil {
		t.Fatalf("loopback http: %v\n%s", err, out)
	}
	out, err = run("list")
	if err != nil || !strings.Contains(out, "openai") || !strings.Contains(out, "local") || !strings.Contains(out, "gpt-5-nano,gpt-5-mini") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if _, err := run("remove", "openai"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: path})
	if _, ok := cfg.Proxy.Upstreams["openai"]; ok || len(cfg.Proxy.AppLanes.Models["openai"]) != 0 {
		t.Fatalf("remove left the lane: %v %v", cfg.Proxy.Upstreams, cfg.Proxy.AppLanes.Models)
	}
	if _, err := run("remove", "openai"); err == nil {
		t.Fatal("removing a missing lane must fail")
	}
}

// TestAppsLaneListStatesPerProcessCaps (hosted AI gateway review L5): with
// [observability] off there is no recorded app spend to read, so the list
// says the caps count only this daemon's calls since it started; with it on
// the line is absent.
func TestAppsLaneListStatesPerProcessCaps(t *testing.T) {
	for _, tc := range []struct {
		name, toml string
		perProc    bool
	}{
		{"observability off", "[proxy]\nport = 8820\n[proxy.upstreams]\nopenai = \"https://api.openai.com\"\n", true},
		{"observability on", "[observability]\nenabled = true\n[proxy]\nport = 8820\n[proxy.upstreams]\nopenai = \"https://api.openai.com\"\n", false},
	} {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := newAppsLaneCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"list", "--config", path})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, out.String())
		}
		if got := strings.Contains(out.String(), "Caps are per daemon process"); got != tc.perProc {
			t.Errorf("%s: per-process line shown=%v, want %v:\n%s", tc.name, got, tc.perProc, out.String())
		}
	}
}
