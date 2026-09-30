package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
)

// Agent Access P4 goldens for the relay's per-format config writer (doc3
// §12.1 stdio-wrapper transformation + remote-entry spelling; Sol P3+P4
// findings 2 + 7): per format - a stdio entry is REPLACED by the wrapper
// with the original restorable (env KEY names only in the staged
// original, values kept in the file for the client to hand the wrapper),
// observer's own server and a remote sibling are never wrapped, the relay
// remote entry is spelled per client, a re-stage is a no-op, Revert puts
// only the relay-owned entries back and preserves an edit made in
// between, and Commit refuses under its CAS. The writer journals NOTHING:
// the rows below are derived from the stage exactly as the projector
// derives them.

const (
	observerBin = "/usr/local/bin/observer"
	relayURL    = "http://127.0.0.1:8858/mcp/github"
	relayName   = "superbased-github"
)

var (
	wrapSpec     = project.WrapSpec{Command: observerBin, ConfigPath: "/home/u/.observer/config.toml"}
	relayHeaders = map[string]string{"X-SBO-VServer": "github"}
	remoteOnly   = project.Desired{Remote: []project.RemoteEntry{{Name: relayName, URL: relayURL, Headers: relayHeaders}}}
	desiredAll   = project.Desired{Wrap: &wrapSpec, Remote: remoteOnly.Remote}
)

func newRelayRegistrar(t *testing.T) (*Registrar, string) {
	t.Helper()
	home := t.TempDir()
	r, err := NewRegistrar(RegisterOptions{BinaryPath: observerBin, HomeDir: home})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return r, home
}

// jsonClientCase is one shared-JSON client with its grounded remote entry
// spelling (the per-client Remote support table in the lane report).
type jsonClientCase struct {
	tool string
	path string
	want map[string]any
}

func jsonClientCases(home string) []jsonClientCase {
	hdrs := map[string]any{"X-SBO-VServer": "github"}
	return []jsonClientCase{
		{
			"claude-code", filepath.Join(home, ".claude.json"),
			map[string]any{"type": "http", "url": relayURL, "headers": hdrs},
		},
		{
			"cursor", filepath.Join(home, ".cursor", "mcp.json"),
			map[string]any{"url": relayURL, "headers": hdrs},
		},
		{
			"cline", locate.ClineSettingsPath(home, runtime.GOOS),
			map[string]any{"type": "streamableHttp", "url": relayURL, "headers": hdrs, "disabled": false},
		},
		{
			"droid", filepath.Join(home, ".factory", "mcp.json"),
			map[string]any{"type": "http", "url": relayURL, "headers": hdrs, "disabled": false},
		},
		{
			"command-code", filepath.Join(home, ".commandcode", "mcp.json"),
			map[string]any{"transport": "http", "enabled": true, "url": relayURL, "headers": hdrs},
		},
	}
}

func readJSONTop(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	top := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse %s: %v: %s", path, err, body)
	}
	return top
}

func serversOf(t *testing.T, top map[string]json.RawMessage, key string) map[string]json.RawMessage {
	t.Helper()
	servers := map[string]json.RawMessage{}
	if raw, ok := top[key]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil {
			t.Fatalf("parse %s: %v", key, err)
		}
	}
	return servers
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// rowsFromStage derives the journal rows the projector would from a stage.
func rowsFromStage(c project.Client, st project.Staged) []project.JournalRow {
	var rows []project.JournalRow
	for _, w := range st.Wrapped {
		rows = append(rows, project.JournalRow{
			Tool: c.Tool, ConfigPath: c.ConfigPath, EntryKey: w.Key,
			OrigCommand: w.Command, OrigArgs: w.Args, OrigCwd: w.Cwd, OrigEnvRefs: w.EnvKeys,
		})
	}
	for _, k := range st.RemoteKeys {
		rows = append(rows, project.JournalRow{Tool: c.Tool, ConfigPath: c.ConfigPath, EntryKey: k, OrigCommand: project.RemoteOrigCommand})
	}
	return rows
}

// priorJSON is deliberately odd (key order, spacing, a remote sibling with
// url/type/headers/env, two stdio siblings - one carrying an env VALUE and
// a cwd and an extra field, observer's own server - and an unrelated
// top-level key) so a lossy round-trip is loud.
const priorJSON = `{
    "zzzTop":   {"shown": true},
  "mcpServers": {
        "other-remote": {"url": "https://x.example/mcp", "type": "sse", "headers": {"X-A": "1"}, "env": {"K": "v"}},
    "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "ghp_SECRETVALUE"}, "cwd": "/repo", "timeout": 30},
    "noargs": {"command": "/opt/plain"},
    "observer": {"command": "/usr/local/bin/observer", "args": ["serve"]}
  }
}
`

const wantWrapArgsFmt = "mcp-relay wrap --client %s --server %s --config /home/u/.observer/config.toml"

func TestRelayWriter_SharedJSONWrapTable(t *testing.T) {
	ctx := context.Background()
	for _, tc := range jsonClientCases("") {
		t.Run(tc.tool, func(t *testing.T) {
			r, home := newRelayRegistrar(t)
			var path string
			var wantRemote map[string]any
			for _, c := range jsonClientCases(home) {
				if c.tool == tc.tool {
					path, wantRemote = c.path, c.want
				}
			}
			writeConfig(t, path, priorJSON)
			c := project.Client{Tool: tc.tool, ConfigPath: path, Format: string(locate.FormatMCPServersJSON), Verified: true}

			st, err := r.Stage(ctx, c, desiredAll)
			if err != nil {
				t.Fatalf("Stage: %v", err)
			}
			if !st.Changed || string(st.Before) != priorJSON || len(st.Wrapped) != 2 || strings.Join(st.RemoteKeys, ",") != relayName {
				t.Fatalf("staged %+v", st)
			}
			gh, noargs := st.Wrapped[0], st.Wrapped[1]
			if gh.Key != "gh" || gh.Command != "npx" || strings.Join(gh.Args, " ") != "-y @modelcontextprotocol/server-github" || gh.Cwd != "/repo" || strings.Join(gh.EnvKeys, ",") != "GITHUB_TOKEN" {
				t.Fatalf("gh original %+v", gh)
			}
			if noargs.Key != "noargs" || noargs.Command != "/opt/plain" || len(noargs.Args) != 0 || noargs.EnvKeys != nil {
				t.Fatalf("noargs original %+v", noargs)
			}
			for _, w := range st.Wrapped {
				if raw := mustJSON(t, w); strings.Contains(string(raw), "SECRETVALUE") {
					t.Fatalf("a secret VALUE reached the staged original: %s", raw)
				}
			}
			// Nothing on disk yet.
			if got, _ := os.ReadFile(path); string(got) != priorJSON {
				t.Fatal("Stage touched the file")
			}
			if err := r.Commit(ctx, c, st); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if got, _ := os.ReadFile(path); string(got) != string(st.After) {
				t.Fatal("Commit wrote something other than the staged bytes")
			}
			if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
				t.Fatalf("Commit changed the mode to %o", fi.Mode().Perm())
			}
			top := readJSONTop(t, path)
			if _, ok := top["zzzTop"]; !ok {
				t.Error("unrelated top-level key clobbered")
			}
			servers := serversOf(t, top, "mcpServers")
			if len(servers) != 5 {
				t.Fatalf("want 5 servers, got %v", servers)
			}
			var ghEntry map[string]any
			_ = json.Unmarshal(servers["gh"], &ghEntry)
			if ghEntry["command"] != observerBin || strings.Join(toStrings(ghEntry["args"]), " ") != wrapArgs(tc.tool, "gh") {
				t.Fatalf("gh not wrapped: %v", ghEntry)
			}
			if ghEntry["env"].(map[string]any)["GITHUB_TOKEN"] != "ghp_SECRETVALUE" || ghEntry["cwd"] != "/repo" || ghEntry["timeout"] != float64(30) {
				t.Fatalf("wrapped entry lost a field: %v", ghEntry)
			}
			var na map[string]any
			_ = json.Unmarshal(servers["noargs"], &na)
			if na["command"] != observerBin || strings.Join(toStrings(na["args"]), " ") != wrapArgs(tc.tool, "noargs") {
				t.Fatalf("noargs not wrapped: %v", na)
			}
			if !jsonEquivalent(servers["observer"], []byte(`{"command":"/usr/local/bin/observer","args":["serve"]}`)) {
				t.Fatalf("observer's own server must never be wrapped: %s", servers["observer"])
			}
			if !jsonEquivalent(servers["other-remote"], []byte(`{"url":"https://x.example/mcp","type":"sse","headers":{"X-A":"1"},"env":{"K":"v"}}`)) {
				t.Fatalf("remote sibling changed: %s", servers["other-remote"])
			}
			if !jsonEquivalent(servers[relayName], mustJSON(t, wantRemote)) {
				t.Fatalf("relay entry = %s, want %s", servers[relayName], mustJSON(t, wantRemote))
			}

			// Idempotent: a re-stage of the same desired state changes nothing.
			st2, err := r.Stage(ctx, c, desiredAll)
			if err != nil || st2.Changed || len(st2.Wrapped) != 0 || len(st2.RemoteKeys) != 0 {
				t.Fatalf("re-stage %+v %v", st2, err)
			}

			// An edit between projection and disable survives the reversal.
			edited := strings.Replace(string(st.After), `"zzzTop": {`, `"zzzTop": {"edited": 1, `, 1)
			if edited == string(st.After) {
				t.Fatal("fixture edit did not apply")
			}
			if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := r.Revert(ctx, c, rowsFromStage(c, st)); err != nil {
				t.Fatalf("Revert: %v", err)
			}
			top = readJSONTop(t, path)
			if !strings.Contains(string(top["zzzTop"]), `"edited"`) {
				t.Fatal("post-projection edit lost by the reversal")
			}
			servers = serversOf(t, top, "mcpServers")
			if _, ok := servers[relayName]; ok {
				t.Fatal("relay remote entry not deleted")
			}
			if !jsonEquivalent(servers["gh"], []byte(`{"command":"npx","args":["-y","@modelcontextprotocol/server-github"],"env":{"GITHUB_TOKEN":"ghp_SECRETVALUE"},"cwd":"/repo","timeout":30}`)) {
				t.Fatalf("gh not put back: %s", servers["gh"])
			}
			if !jsonEquivalent(servers["noargs"], []byte(`{"command":"/opt/plain","args":[]}`)) {
				t.Fatalf("noargs not put back: %s", servers["noargs"])
			}
			if len(servers) != 4 {
				t.Fatalf("servers after revert %v", servers)
			}
			// Reverting again is a no-op (nothing is the wrapper any more).
			before, _ := os.ReadFile(path)
			if err := r.Revert(ctx, c, rowsFromStage(c, st)); err != nil {
				t.Fatal(err)
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Fatal("second revert rewrote the file")
			}
		})
	}
}

func wrapArgs(tool, key string) string {
	return strings.Replace(strings.Replace(wantWrapArgsFmt, "%s", tool, 1), "%s", key, 1)
}

func toStrings(v any) []string {
	var out []string
	if s, ok := v.([]any); ok {
		for _, a := range s {
			out = append(out, a.(string))
		}
	}
	return out
}

// priorCodexTOML carries a comment (lost on any TOML rewrite - the journaled
// backup is what makes disable byte-identical), an unrelated table, a stdio
// server with env + cwd + a timeout, observer's own server and a remote one.
const priorCodexTOML = `# codex config
model = "gpt-5"

[sandbox]
mode = "workspace-write"

[mcp_servers.gh]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
cwd = "/repo"
startup_timeout_sec = 20

[mcp_servers.gh.env]
GITHUB_TOKEN = "ghp_SECRETVALUE"

[mcp_servers.observer]
command = "/usr/local/bin/observer"
args = ["serve"]

[mcp_servers.remote]
url = "https://x.example/mcp"
`

func TestRelayWriter_CodexTOMLWrapTable(t *testing.T) {
	ctx := context.Background()
	r, home := newRelayRegistrar(t)
	path := filepath.Join(home, ".codex", "config.toml")
	writeConfig(t, path, priorCodexTOML)
	c := project.Client{Tool: "codex", ConfigPath: path, Format: string(locate.FormatCodexTOML), Verified: true}

	// SSE is not grounded for codex (url = streamable HTTP, no type key).
	if _, err := r.Stage(ctx, c, project.Desired{Remote: []project.RemoteEntry{{Name: relayName, URL: relayURL, Transport: "sse"}}}); err == nil || !strings.Contains(err.Error(), "not grounded") {
		t.Errorf("codex SSE should be refused: %v", err)
	}
	st, err := r.Stage(ctx, c, desiredAll)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !st.Changed || len(st.Wrapped) != 1 || st.Wrapped[0].Key != "gh" || st.Wrapped[0].Cwd != "/repo" || strings.Join(st.Wrapped[0].EnvKeys, ",") != "GITHUB_TOKEN" || strings.Join(st.RemoteKeys, ",") != relayName {
		t.Fatalf("staged %+v", st)
	}
	if err := r.Commit(ctx, c, st); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	root := map[string]any{}
	if err := toml.Unmarshal(body, &root); err != nil {
		t.Fatalf("parse: %v\n%s", err, body)
	}
	if root["model"] != "gpt-5" || root["sandbox"].(map[string]any)["mode"] != "workspace-write" {
		t.Fatalf("unrelated tables changed: %s", body)
	}
	servers := root["mcp_servers"].(map[string]any)
	gh := servers["gh"].(map[string]any)
	if gh["command"] != observerBin || strings.Join(toStrings(gh["args"]), " ") != wrapArgs("codex", "gh") || gh["cwd"] != "/repo" || gh["startup_timeout_sec"] != int64(20) {
		t.Fatalf("gh: %v", gh)
	}
	if gh["env"].(map[string]any)["GITHUB_TOKEN"] != "ghp_SECRETVALUE" {
		t.Fatalf("env table lost: %v", gh)
	}
	if obs := servers["observer"].(map[string]any); obs["command"] != observerBin || strings.Join(toStrings(obs["args"]), " ") != "serve" {
		t.Fatalf("observer wrapped: %v", obs)
	}
	if rem := servers["remote"].(map[string]any); rem["url"] != "https://x.example/mcp" {
		t.Fatalf("remote sibling changed: %v", rem)
	}
	relay := servers[relayName].(map[string]any)
	if relay["url"] != relayURL || relay["http_headers"].(map[string]any)["X-SBO-VServer"] != "github" {
		t.Fatalf("relay entry: %v", relay)
	}
	for _, forbidden := range []string{"bearer_token_env_var", "env_http_headers", "type", "transport"} {
		if _, ok := relay[forbidden]; ok {
			t.Errorf("codex remote entry must not carry %s", forbidden)
		}
	}
	if st2, err := r.Stage(ctx, c, desiredAll); err != nil || st2.Changed {
		t.Fatalf("re-stage %+v %v", st2, err)
	}
	// Edit between (a new key), then revert: edit kept, gh back, relay gone.
	if err := os.WriteFile(path, append([]byte("edited_later = true\n"), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Revert(ctx, c, rowsFromStage(c, st)); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(path)
	root = map[string]any{}
	if err := toml.Unmarshal(body, &root); err != nil {
		t.Fatal(err)
	}
	if root["edited_later"] != true {
		t.Fatal("post-projection edit lost")
	}
	servers = root["mcp_servers"].(map[string]any)
	gh = servers["gh"].(map[string]any)
	if gh["command"] != "npx" || strings.Join(toStrings(gh["args"]), " ") != "-y @modelcontextprotocol/server-github" || gh["env"].(map[string]any)["GITHUB_TOKEN"] != "ghp_SECRETVALUE" {
		t.Fatalf("gh not put back: %v", gh)
	}
	if _, ok := servers[relayName]; ok {
		t.Fatal("relay entry not deleted")
	}
	if len(servers) != 3 {
		t.Fatalf("servers %v", servers)
	}
}

const priorOpenCode = `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "gh": {"type": "local", "command": ["npx", "-y", "gh-mcp"], "enabled": true, "environment": {"GITHUB_TOKEN": "ghp_SECRETVALUE"}},
    "untyped": {"command": ["/opt/plain"]},
    "observer": {"type": "local", "command": ["/usr/local/bin/observer", "serve"], "enabled": true},
    "remote": {"type": "remote", "url": "https://x.example/mcp", "enabled": true}
  },
  "plugin": ["x"]
}
`

func TestRelayWriter_OpenCodeWrapTable(t *testing.T) {
	ctx := context.Background()
	r, home := newRelayRegistrar(t)
	path := filepath.Join(home, ".config", "opencode", "opencode.json")
	writeConfig(t, path, priorOpenCode)
	c := project.Client{Tool: "opencode", ConfigPath: path, Format: string(locate.FormatOpenCodeJSON), Verified: true}
	st, err := r.Stage(ctx, c, desiredAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Wrapped) != 2 || st.Wrapped[0].Key != "gh" || st.Wrapped[0].Command != "npx" || strings.Join(st.Wrapped[0].Args, " ") != "-y gh-mcp" || strings.Join(st.Wrapped[0].EnvKeys, ",") != "GITHUB_TOKEN" || st.Wrapped[1].Key != "untyped" {
		t.Fatalf("staged %+v", st.Wrapped)
	}
	if err := r.Commit(ctx, c, st); err != nil {
		t.Fatal(err)
	}
	top := readJSONTop(t, path)
	if _, ok := top["$schema"]; !ok || !jsonEquivalent(top["plugin"], []byte(`["x"]`)) {
		t.Fatalf("unrelated keys changed: %v", top)
	}
	servers := serversOf(t, top, "mcp")
	var gh map[string]any
	_ = json.Unmarshal(servers["gh"], &gh)
	wantCmd := append([]string{observerBin}, strings.Split(wrapArgs("opencode", "gh"), " ")...)
	if gh["type"] != "local" || strings.Join(toStrings(gh["command"]), "\x00") != strings.Join(wantCmd, "\x00") || gh["enabled"] != true || gh["environment"].(map[string]any)["GITHUB_TOKEN"] != "ghp_SECRETVALUE" {
		t.Fatalf("gh: %v", gh)
	}
	if !jsonEquivalent(servers["observer"], []byte(`{"type":"local","command":["/usr/local/bin/observer","serve"],"enabled":true}`)) {
		t.Fatalf("observer wrapped: %s", servers["observer"])
	}
	if !jsonEquivalent(servers["remote"], []byte(`{"type":"remote","url":"https://x.example/mcp","enabled":true}`)) {
		t.Fatalf("remote sibling: %s", servers["remote"])
	}
	if !jsonEquivalent(servers[relayName], []byte(`{"type":"remote","url":"`+relayURL+`","enabled":true,"headers":{"X-SBO-VServer":"github"}}`)) {
		t.Fatalf("relay entry: %s", servers[relayName])
	}
	if st2, err := r.Stage(ctx, c, desiredAll); err != nil || st2.Changed {
		t.Fatalf("re-stage %+v %v", st2, err)
	}
	if err := r.Revert(ctx, c, rowsFromStage(c, st)); err != nil {
		t.Fatal(err)
	}
	servers = serversOf(t, readJSONTop(t, path), "mcp")
	if !jsonEquivalent(servers["gh"], []byte(`{"type":"local","command":["npx","-y","gh-mcp"],"enabled":true,"environment":{"GITHUB_TOKEN":"ghp_SECRETVALUE"}}`)) || !jsonEquivalent(servers["untyped"], []byte(`{"command":["/opt/plain"]}`)) {
		t.Fatalf("not put back: %s / %s", servers["gh"], servers["untyped"])
	}
	if _, ok := servers[relayName]; ok || len(servers) != 4 {
		t.Fatalf("servers %v", servers)
	}
}

// TestRelayWriter_AbsentConfigRemoteOnly: a fresh (absent) file stages with
// Before=nil, Commit creates it 0600, Revert removes the relay entry and
// leaves an empty document (a reversal never deletes a file - only the
// whole-file restore of an `.absent` backup does).
func TestRelayWriter_AbsentConfigRemoteOnly(t *testing.T) {
	ctx := context.Background()
	r, home := newRelayRegistrar(t)
	path := filepath.Join(home, ".cursor", "mcp.json")
	c := project.Client{Tool: "cursor", ConfigPath: path, Format: string(locate.FormatMCPServersJSON), Verified: true}
	st, err := r.Stage(ctx, c, remoteOnly)
	if err != nil || !st.Changed || st.Before != nil || len(st.Wrapped) != 0 || len(st.RemoteKeys) != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	if err := r.Commit(ctx, c, st); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("created file: %v %v", fi, err)
	}
	if err := r.Revert(ctx, c, rowsFromStage(c, st)); err != nil {
		t.Fatal(err)
	}
	top := readJSONTop(t, path)
	if len(top) != 0 {
		t.Fatalf("expected an empty document after reversal, got %v", top)
	}
	// A wrap-only desired state on an absent file is a no-op.
	if st, err := r.Stage(ctx, c, project.Desired{Wrap: &wrapSpec}); err != nil || st.Changed {
		t.Fatalf("%+v %v", st, err)
	}
}

// TestRelayWriter_CommitCAS: the file moved between Stage and Commit.
func TestRelayWriter_CommitCAS(t *testing.T) {
	ctx := context.Background()
	r, home := newRelayRegistrar(t)
	path := filepath.Join(home, ".claude.json")
	writeConfig(t, path, priorJSON)
	c := project.Client{Tool: "claude-code", ConfigPath: path, Format: string(locate.FormatMCPServersJSON), Verified: true}
	st, err := r.Stage(ctx, c, desiredAll)
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.Replace(priorJSON, `"shown": true`, `"shown": false`, 1)
	if err := os.WriteFile(path, []byte(moved), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(ctx, c, st); !errors.Is(err, project.ErrConfigChanged) || !strings.Contains(err.Error(), path) {
		t.Fatalf("want ErrConfigChanged naming the file, got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != moved {
		t.Fatal("a refused commit touched the file")
	}
	// An absent-vs-present mismatch is a CAS refusal too.
	_ = os.Remove(path)
	if err := r.Commit(ctx, c, st); !errors.Is(err, project.ErrConfigChanged) {
		t.Fatalf("%v", err)
	}
}

// TestRelayWriter_Refusals: an Authorization header, headers on a client
// that grounds none, a tool without a locate row, an unwrappable format.
func TestRelayWriter_Refusals(t *testing.T) {
	ctx := context.Background()
	r, home := newRelayRegistrar(t)
	cc := project.Client{Tool: "claude-code", ConfigPath: filepath.Join(home, ".claude.json"), Format: string(locate.FormatMCPServersJSON), Verified: true}
	for _, hdr := range []string{"Authorization", "authorization", "Proxy-Authorization"} {
		d := project.Desired{Remote: []project.RemoteEntry{{Name: relayName, URL: relayURL, Headers: map[string]string{hdr: "Bearer x"}}}}
		if _, err := r.Stage(ctx, cc, d); err == nil || !strings.Contains(err.Error(), "never carries a secret") {
			t.Errorf("%s header must be refused: %v", hdr, err)
		}
	}
	if _, err := r.Stage(ctx, project.Client{Tool: "hermes", Verified: true}, desiredAll); err == nil || !strings.Contains(err.Error(), "no MCP config location") {
		t.Errorf("hermes (no locate row) must be refused honestly: %v", err)
	}
	if _, err := r.Stage(ctx, project.Client{Tool: "cursor", ConfigPath: "/x", Format: "yaml", Verified: true}, desiredAll); err == nil || !strings.Contains(err.Error(), "no stdio-wrap writer") {
		t.Errorf("unknown format must be refused: %v", err)
	}
	if _, err := r.Stage(ctx, project.Client{Tool: "nothing", Verified: true}, desiredAll); err == nil {
		t.Error("unknown tool accepted")
	}
	// A restore-time client (tool + path only) resolves its format.
	writeConfig(t, cc.ConfigPath, priorJSON)
	if err := r.Revert(ctx, project.Client{Tool: "claude-code", ConfigPath: cc.ConfigPath}, nil); err != nil {
		t.Fatalf("format resolution on revert: %v", err)
	}
}

// TestRelayClients_InstalledAndVerified: every installed tool with a locate
// row is a client; Verified follows the wrap-writer table; the cross-OS
// cline-windows bridge is never a relay client.
func TestRelayClients_InstalledAndVerified(t *testing.T) {
	home := t.TempDir()
	winHome := filepath.Join(home, "mnt", "c", "Users", "alice")
	for _, d := range []string{".claude", ".cursor", ".codex", filepath.Join(".config", "opencode"), ".factory", ".commandcode"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(locate.ClineSettingsPath(winHome, "windows")), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistrar(RegisterOptions{BinaryPath: observerBin, HomeDir: home, WindowsClineHome: winHome})
	if err != nil {
		t.Fatal(err)
	}
	installed := strings.Join(r.Installed(), ",")
	if !strings.Contains(installed, "cline-windows") {
		t.Fatalf("fixture: cline-windows should be installed: %s", installed)
	}
	clients := r.RelayClients()
	seen := map[string]project.Client{}
	for _, c := range clients {
		seen[c.Tool] = c
		if c.Tool == "cline-windows" {
			t.Error("cline-windows must not be a relay client (the wrapper cannot spawn a Windows-side original from WSL)")
		}
		if !c.Verified || c.ConfigPath == "" || c.Format == "" {
			t.Errorf("client %+v", c)
		}
	}
	for _, want := range []string{"claude-code", "cursor", "codex", "opencode", "droid", "command-code"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("%s missing from RelayClients: %v", want, clients)
		}
	}
	if seen["codex"].Format != string(locate.FormatCodexTOML) || seen["opencode"].Format != string(locate.FormatOpenCodeJSON) {
		t.Errorf("formats %+v", seen)
	}
}

// TestWrapWriterImplemented pins the registry-format -> writer table.
func TestWrapWriterImplemented(t *testing.T) {
	cases := map[integration.MCPFormat]bool{
		integration.MCPServersJSON:  true,
		integration.MCPCodexTOML:    true,
		integration.MCPOpenCodeJSON: true,
		integration.MCPHermesYAML:   false,
		"":                          false,
	}
	for f, want := range cases {
		if got := WrapWriterImplemented(f); got != want {
			t.Errorf("WrapWriterImplemented(%q) = %v, want %v", f, got, want)
		}
	}
}

// TestRemoteRegistryWriterAgreement pins the registry<->writer contract doc3
// §12.1 (R8.24.u) demands: every row whose Remote target is Implemented
// resolves to a locate row + a wrap writer here, and every grounded-but-
// unwired row (hermes) is refused with the honest reason - never silently
// written, never silently skipped. Every MCP row's stdio format either has
// a wrap writer or is honestly unwrappable.
func TestRemoteRegistryWriterAgreement(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.MCP == nil {
			continue
		}
		t.Run(c.Tool, func(t *testing.T) {
			_, ok := locate.ForClient(c.Tool, "/h")
			if WrapWriterImplemented(c.MCP.Format) != ok {
				t.Errorf("wrap writer for %s = %v but locate row = %v", c.MCP.Format, WrapWriterImplemented(c.MCP.Format), ok)
			}
			if c.MCP.Remote == nil {
				return
			}
			_, err := remoteTargetFor(c.Tool)
			if c.MCP.Remote.Implemented {
				if err != nil || !ok || !WrapWriterImplemented(c.MCP.Format) {
					t.Fatalf("Remote.Implemented but no writer/locate row: %v %v", err, ok)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "no writer") {
				t.Errorf("unimplemented row must be refused honestly: %v", err)
			}
		})
	}
	if _, err := remoteTargetFor("cline-windows"); err != nil {
		t.Errorf("cline-windows bridge remote target: %v", err)
	}
	if _, err := remoteTargetFor("cursor-windows"); err == nil {
		t.Error("cursor has no cross-OS bridge")
	}
}
