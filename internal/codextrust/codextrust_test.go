package codextrust

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// liveCmd is the hook command Observer 1.34.0-rc.11 registered on demo
// node 1; the hashes below are the trusted_hash values Codex 0.160.0
// recorded for those six entries (read from the node's
// ~/.codex/config.toml on 2026-10-03, read-only).
const liveCmd = "/usr/local/lib/node_modules/@superbased/observer/node_modules/@superbased/observer-linux-x64/bin/observer hook codex %s --config /home/azureuser/.observer/config.toml"

var liveVectors = []struct{ event, hash string }{
	{"PreToolUse", "bc5b883029b83c23f2f3e14f4cad6d48c76cf364eda3b845d27fceb822b79a7b"},
	{"PermissionRequest", "e7b755a64198b345742719557786507347e1a6d19a05e104d0f856f9bc97a3a3"},
	{"PostToolUse", "adc56c2c7f7dbe89edcd7267e2caaa3f36a737126d703b31c69495866eff2f96"},
	{"SessionStart", "ec13a336f52bdc0d753f8c1619fe88a9fba41027fac331abb134da5fb15ed5c4"},
	{"UserPromptSubmit", "84766e91572eb9dbaf14332c63a9ff1ac70f6e15a5bcfa8b70b82efcb50d852f"},
	{"Stop", "f848e51ec2a88b6a4fabdbfcf6b30461da39e581d78c8344f5fa80e2f0ffeff9"},
}

func TestHashReproducesLiveCodexTrust(t *testing.T) {
	star := "*"
	for _, v := range liveVectors {
		got := candidateHashes(CamelToSnake(v.event), &star, fmt.Sprintf(liveCmd, v.event), nil, nil, nil)
		if !containsStr(got, v.hash) {
			t.Errorf("%s: candidates %v do not include the live hash %s", v.event, got, v.hash)
		}
	}
}

// TestClassifyNormalizesWindowsTrustKeys: a Windows Codex keys trust with
// its own spelling of the hooks.json path (drive letter, backslashes, maybe
// the \\?\ prefix, any case); with NormalizePath the entry a WSL daemon
// reads through /mnt/c classifies as trusted, and without it as untrusted
// (the pre-fix behaviour, kept for a nil normalizer).
func TestClassifyNormalizesWindowsTrustKeys(t *testing.T) {
	norm := func(p string) string {
		p = strings.ReplaceAll(strings.TrimPrefix(p, `\\?\`), `\`, "/")
		if len(p) > 2 && p[1] == ':' {
			p = "/mnt/" + strings.ToLower(p[:1]) + p[2:]
		}
		return strings.ToLower(p)
	}
	star := "*"
	hash := Hash("pre_tool_use", &star, fmt.Sprintf(liveCmd, "PreToolUse"), 600, false, nil)
	for _, winPath := range []string{`C:\Users\Op\.codex\hooks.json`, `\\?\C:\Users\op\.codex\hooks.json`} {
		cfg := fmt.Sprintf("[hooks.state.%s]\ntrusted_hash = %q\n", strconv.Quote(winPath+":pre_tool_use:0:0"), hash)
		in := Input{
			HooksPath: "/mnt/c/Users/op/.codex/hooks.json", HooksJSON: fixture([]string{"PreToolUse"}, false),
			ConfigTOML: []byte(cfg), Expected: []string{"PreToolUse"},
			Owned: func(c string) bool { return strings.Contains(c, " hook codex ") },
		}
		rep, err := Classify(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := rep.Entries[0].State; got != StateUntrusted {
			t.Errorf("%s without a normalizer: state %s, want untrusted (byte-exact keys)", winPath, got)
		}
		in.NormalizePath = norm
		rep, err = Classify(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := rep.Entries[0].State; got != StateTrusted || !rep.HashVerified {
			t.Errorf("%s with a normalizer: state %s verified %v, want trusted and verified", winPath, got, rep.HashVerified)
		}
	}
}

func TestSplitStateKey(t *testing.T) {
	for k, want := range map[string][2]string{
		`C:\Users\u\.codex\hooks.json:pre_tool_use:0:0`: {`C:\Users\u\.codex\hooks.json`, ":pre_tool_use:0:0"},
		"/home/u/.codex/hooks.json:stop:1:2":            {"/home/u/.codex/hooks.json", ":stop:1:2"},
	} {
		p, tail, ok := splitStateKey(k)
		if !ok || p != want[0] || tail != want[1] {
			t.Errorf("splitStateKey(%q) = %q, %q, %v", k, p, tail, ok)
		}
	}
	if _, _, ok := splitStateKey("no-colons"); ok {
		t.Error("splitStateKey accepted a key without the event tail")
	}
}

func TestCamelToSnake(t *testing.T) {
	for in, want := range map[string]string{
		"PreToolUse": "pre_tool_use", "Stop": "stop", "UserPromptSubmit": "user_prompt_submit",
		"SessionEnd": "session_end", "": "",
	} {
		if got := CamelToSnake(in); got != want {
			t.Errorf("CamelToSnake(%q) = %q, want %q", in, got, want)
		}
	}
}

// fixture builds hooks.json (one Observer group per event, optional extra
// user entry) and a config.toml from per-event state lines.
func fixture(events []string, user bool) []byte {
	hooks := map[string]any{}
	for _, e := range events {
		hooks[e] = []any{map[string]any{"matcher": "*", "hooks": []any{
			map[string]any{"type": "command", "command": fmt.Sprintf(liveCmd, e)},
		}}}
	}
	if user {
		hooks["PostToolUse"] = append([]any{map[string]any{"matcher": "*", "hooks": []any{
			map[string]any{"type": "command", "command": "/usr/local/bin/my-policy"},
		}}}, anySlice(hooks["PostToolUse"])...)
	}
	b, _ := json.Marshal(map[string]any{"hooks": hooks})
	return b
}

func anySlice(v any) []any { s, _ := v.([]any); return s }

const hooksPath = "/home/u/.codex/hooks.json"

func stateLine(event string, gi int, body string) string {
	return fmt.Sprintf("[hooks.state.%s]\n%s\n", strconv.Quote(fmt.Sprintf("%s:%s:%d:0", hooksPath, CamelToSnake(event), gi)), body)
}

func liveHash(event string) string {
	for _, v := range liveVectors {
		if v.event == event {
			return "sha256:" + v.hash
		}
	}
	return ""
}

func owned(cmd string) bool { return strings.Contains(cmd, " hook codex ") }

// TestClassify is the rule table: one row per state and per
// verification mode.
func TestClassify(t *testing.T) {
	expected := []string{"PreToolUse", "SessionStart", "Stop", "SubagentStart"}
	present := []string{"PreToolUse", "SessionStart", "Stop"}
	trusted := func(e string) string { return stateLine(e, 0, "trusted_hash = \""+liveHash(e)+"\"") }
	for _, tc := range []struct {
		name     string
		cfg      *string
		user     bool
		want     map[string]State
		verified bool
	}{
		{
			name: "no config.toml: every present event untrusted, the new one missing",
			want: map[string]State{"PreToolUse": StateUntrusted, "SessionStart": StateUntrusted, "Stop": StateUntrusted, "SubagentStart": StateMissing},
		},
		{
			name:     "all present trusted with live hashes",
			cfg:      ptr("[features]\nhooks = true\n" + trusted("PreToolUse") + trusted("SessionStart") + trusted("Stop")),
			want:     map[string]State{"PreToolUse": StateTrusted, "SessionStart": StateTrusted, "Stop": StateTrusted, "SubagentStart": StateMissing},
			verified: true,
		},
		{
			name: "a stale hash beside a verified one is modified",
			cfg: ptr(trusted("PreToolUse") + stateLine("Stop", 0, `trusted_hash = "sha256:0000"`) +
				stateLine("SessionStart", 0, "trusted_hash = \""+liveHash("SessionStart")+"\"\nenabled = false")),
			want:     map[string]State{"PreToolUse": StateTrusted, "SessionStart": StateDisabled, "Stop": StateModified, "SubagentStart": StateMissing},
			verified: true,
		},
		{
			name: "no hash reproduces: recorded approvals are taken at their word",
			cfg:  ptr(stateLine("PreToolUse", 0, `trusted_hash = "sha256:abc"`) + stateLine("Stop", 0, `trusted_hash = "sha256:def"`)),
			want: map[string]State{"PreToolUse": StateTrusted, "SessionStart": StateUntrusted, "Stop": StateTrusted, "SubagentStart": StateMissing},
		},
		{
			name: "a user's own trusted entry anchors verification",
			cfg: ptr(stateLine("PostToolUse", 0, `trusted_hash = "`+userHash()+`"`) +
				stateLine("PreToolUse", 0, `trusted_hash = "sha256:0000"`)),
			user:     true,
			want:     map[string]State{"PreToolUse": StateModified, "SessionStart": StateUntrusted, "Stop": StateUntrusted, "SubagentStart": StateMissing},
			verified: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Input{HooksPath: hooksPath, HooksJSON: fixture(present, tc.user), Expected: expected, Owned: owned}
			if tc.cfg != nil {
				in.ConfigTOML = []byte(*tc.cfg)
			}
			rep, err := Classify(in)
			if err != nil {
				t.Fatal(err)
			}
			if rep.HashVerified != tc.verified {
				t.Errorf("HashVerified = %v, want %v", rep.HashVerified, tc.verified)
			}
			got := map[string]State{}
			for _, e := range rep.Entries {
				got[e.Event] = e.State
				if e.Event == "SubagentStart" && !e.Expected {
					t.Errorf("missing event not marked expected")
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("states = %v, want %v", got, tc.want)
			}
		})
	}
}

func userHash() string {
	star := "*"
	return Hash("post_tool_use", &star, "/usr/local/bin/my-policy", defaultTimeoutSec, false, nil)
}

func ptr(s string) *string { return &s }

func TestClassifyRejectsGarbage(t *testing.T) {
	if _, err := Classify(Input{HooksJSON: []byte("{")}); err == nil {
		t.Error("want a parse error for broken hooks.json")
	}
	if _, err := Classify(Input{HooksJSON: fixture([]string{"Stop"}, false), ConfigTOML: []byte("[[")}); err == nil {
		t.Error("want a parse error for broken config.toml")
	}
}

// TestPackageIsPure pins the package free of file, SQL, HTTP and
// fsnotify imports (CLAUDE.md module boundary rule 1).
func TestPackageIsPure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "os", "github.com/fsnotify/fsnotify"},
		Reason:    "internal/codextrust must stay pure",
	})
}
