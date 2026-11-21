package shiptoken

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestResolveNodeProject(t *testing.T) {
	l := ProjectLookup{
		ByRemote: func(raw string) (string, string, bool) {
			if raw == "not a remote" {
				return "", "", false
			}
			return "/home/me/repo", "github.com/acme/repo", true
		},
		ByRemoteHash: func(h string) (string, string, bool) {
			if h == "known" {
				return "/home/me/other", "github.com/acme/other", true
			}
			return "", "", false
		},
	}
	for _, tc := range []struct {
		name      string
		s         orgcontract.SessionRow
		root, rem string
		src       ProjectSource
	}{
		{"raw remote wins", orgcontract.SessionRow{GitRemote: "git@github.com:acme/repo.git", GitRemoteHash: "known", ProjectRoot: "/home/user/repo"}, "/home/me/repo", "github.com/acme/repo", ProjectFromRemote},
		{"a path is not a remote, the hash is tried next", orgcontract.SessionRow{GitRemote: "not a remote", GitRemoteHash: "known"}, "/home/me/other", "github.com/acme/other", ProjectFromRemoteHash},
		{"hash only", orgcontract.SessionRow{GitRemoteHash: "known"}, "/home/me/other", "github.com/acme/other", ProjectFromRemoteHash},
		{"unknown hash", orgcontract.SessionRow{GitRemoteHash: "nope", ProjectRoot: "/home/user/repo"}, UnattributedCloudRoot, "", ProjectUnattributed},
		{"nothing, and the sandbox path is never used", orgcontract.SessionRow{ProjectRoot: "/home/user/repo"}, UnattributedCloudRoot, "", ProjectUnattributed},
	} {
		root, rem, src := ResolveNodeProject(tc.s, l)
		if root != tc.root || rem != tc.rem || src != tc.src {
			t.Errorf("%s: (%q, %q, %s), want (%q, %q, %s)", tc.name, root, rem, src, tc.root, tc.rem, tc.src)
		}
	}
	if root, _, src := ResolveNodeProject(orgcontract.SessionRow{GitRemote: "x"}, ProjectLookup{}); root != UnattributedCloudRoot || src != ProjectUnattributed {
		t.Error("nil lookups must fall through to unattributed")
	}
}

func TestPlanNode(t *testing.T) {
	env := orgcontract.PushEnvelope{
		Sessions: []orgcontract.SessionRow{
			{ID: "s1", GitRemote: "git@github.com:acme/repo.git", GitBranch: "main", ExecutionLocation: "vendor_cloud", VendorSessionRef: "cse_1"},
			{ID: "s2", ExecutionLocation: "mars", VendorSessionRef: "https://bad"},
		},
		Actions: []orgcontract.ActionRow{
			{SessionID: "s1", SourceEventID: "e1", Timestamp: "2026-10-31T10:00:01Z", Tool: "claude-code", ActionType: "read_file", Success: true},
			{SessionID: "orphan", SourceEventID: "e2", Timestamp: "bad time", Tool: "claude-code", ActionType: "run_command"},
		},
		TokenUsage: []orgcontract.TokenUsageRow{{SessionID: "s1", SourceEventID: "t1", Timestamp: "2026-10-31T10:00:02Z", Tool: "claude-code", Model: "m", InputTokens: 10, OutputTokens: 5, Source: "jsonl", Reliability: "reliable"}},
		APITurns:   []orgcontract.APITurnRow{{SessionID: "s1"}},
		SessionLOC: []orgcontract.SessionLOCRow{{}},
	}
	p := PlanNode(env, ProjectLookup{ByRemote: func(string) (string, string, bool) {
		return "cloud:github.com/acme/repo", "github.com/acme/repo", true
	}})
	if len(p.Events) != 2 || len(p.Tokens) != 1 {
		t.Fatalf("plan %+v", p)
	}
	e := p.Events[0]
	if e.ProjectRoot != "cloud:github.com/acme/repo" || e.GitRemote != "github.com/acme/repo" || e.GitBranch != "main" || e.Timestamp.IsZero() {
		t.Errorf("event 0 %+v", e)
	}
	if e.SourceFile != CloudSourcePrefix+"s1" {
		t.Errorf("source file %q, want the stable synthetic one", e.SourceFile)
	}
	if p.Events[1].ProjectRoot != UnattributedCloudRoot || !p.Events[1].Timestamp.IsZero() {
		t.Errorf("orphan event %+v", p.Events[1])
	}
	if p.Tokens[0].InputTokens != 10 || p.Tokens[0].ProjectRoot != "cloud:github.com/acme/repo" {
		t.Errorf("token %+v", p.Tokens[0])
	}
	if len(p.Executions) != 1 || p.Executions[0].SessionID != "s1" || p.Executions[0].VendorSessionRef != "cse_1" {
		t.Errorf("executions %+v (an invalid location and reference must not stamp)", p.Executions)
	}
	if p.NotLanded["api_turns"] != 1 || p.NotLanded["session_loc"] != 1 || len(p.NotLanded) != 2 {
		t.Errorf("not landed %+v", p.NotLanded)
	}
	if p.Projects[ProjectFromRemote] != 1 || p.Projects[ProjectUnattributed] != 1 {
		t.Errorf("projects %+v", p.Projects)
	}
	if !NodeLands("actions") || NodeLands("api_turns") {
		t.Error("NodeLands")
	}
}

// TestSourceFileForNeverKeepsTheSandboxPath pins ledger CLOUDSESS-12: every
// landed row is stored under the synthetic cloud-session key, whatever path
// the sandbox claims, so no node reader can be pointed at a UNC share or a
// local secret file. The key stays stable across re-sends.
func TestSourceFileForNeverKeepsTheSandboxPath(t *testing.T) {
	const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	cases := []struct {
		name            string
		file, hash, sid string
		want            string
	}{
		{"UNC path, no hash", `\attacker.example@SSL\s\a.jsonl`, "", "s1", CloudSourcePrefix + sha256Hex(`\attacker.example@SSL\s\a.jsonl`)},
		{"forward-slash UNC path, no hash", "//attacker.example/s/a.jsonl", "", "s1", CloudSourcePrefix + sha256Hex("//attacker.example/s/a.jsonl")},
		{"home secret file, no hash", "/home/me/.codex/auth.json", "", "s1", CloudSourcePrefix + sha256Hex("/home/me/.codex/auth.json")},
		{"Windows home secret file with its hash", `C:\Users\me\.codex\auth.json`, digest, "s1", CloudSourcePrefix + digest},
		{"metadata-only flush: hash only", "", digest, "s1", CloudSourcePrefix + digest},
		{"prefixed digest is kept", "", "sha256:" + digest, "s1", CloudSourcePrefix + "sha256:" + digest},
		{"a path smuggled in the hash field is re-hashed", "", `\host\s\a.jsonl`, "s1", CloudSourcePrefix + sha256Hex(`\host\s\a.jsonl`)},
		{"an oversize hash is re-hashed", "", strings.Repeat("a", 129), "s1", CloudSourcePrefix + sha256Hex(strings.Repeat("a", 129))},
		{"nothing: the session id", "", "", "s1", CloudSourcePrefix + "s1"},
	}
	for _, tc := range cases {
		got := sourceFileFor(tc.file, tc.hash, tc.sid)
		if got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
		if !strings.HasPrefix(got, CloudSourcePrefix) {
			t.Errorf("%s: %q is not synthetic", tc.name, got)
		}
	}
	// The raw path and its digest land on one key, so a re-send that adds
	// or drops the hash does not duplicate rows.
	if sourceFileFor("/sandbox/a.jsonl", "", "s") != sourceFileFor("", sha256Hex("/sandbox/a.jsonl"), "s") {
		t.Error("raw-path and hash-only sends of one file land on different keys")
	}
	p := PlanNode(orgcontract.PushEnvelope{
		Actions:    []orgcontract.ActionRow{{SessionID: "s1", SourceEventID: "e1", SourceFile: `\host\s\a.jsonl`}},
		TokenUsage: []orgcontract.TokenUsageRow{{SessionID: "s1", SourceEventID: "t1", SourceFile: "/home/me/.ssh/id_ed25519.json"}},
	}, ProjectLookup{})
	if !strings.HasPrefix(p.Events[0].SourceFile, CloudSourcePrefix) || !strings.HasPrefix(p.Tokens[0].SourceFile, CloudSourcePrefix) {
		t.Fatalf("planned source files %q, %q", p.Events[0].SourceFile, p.Tokens[0].SourceFile)
	}
}

func TestSessionOwnership(t *testing.T) {
	const tok, other = "cst_aaaaaaaaaaaaaaaaaaaaaaaa", "cst_bbbbbbbbbbbbbbbbbbbbbbbb"
	cases := []struct {
		name   string
		exists bool
		via    string
		want   string
	}{
		{"new session", false, "", ""},
		{"created by this token", true, tok, ""},
		{"captured by the node itself", true, "", SessionSkipLocal},
		{"created by another token", true, other, SessionSkipOtherToken},
	}
	for _, tc := range cases {
		if got := SessionOwnership(tc.exists, tc.via, tok); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestWithoutSessions(t *testing.T) {
	env := orgcontract.PushEnvelope{
		Sessions:   []orgcontract.SessionRow{{ID: "keep"}, {ID: "local"}},
		Actions:    []orgcontract.ActionRow{{SessionID: "keep"}, {SessionID: "local"}, {SessionID: "local"}},
		TokenUsage: []orgcontract.TokenUsageRow{{SessionID: "local"}, {SessionID: "orphan"}},
		APITurns:   []orgcontract.APITurnRow{{SessionID: "local"}},
	}
	if ids := EnvelopeSessionIDs(env); strings.Join(ids, ",") != "keep,local,orphan" {
		t.Fatalf("session ids %v", ids)
	}
	out, removed := WithoutSessions(env, map[string]bool{"local": true})
	if len(out.Sessions) != 1 || len(out.Actions) != 1 || len(out.TokenUsage) != 1 || len(out.APITurns) != 1 {
		t.Fatalf("filtered %+v", out)
	}
	if removed["sessions"] != 1 || removed["actions"] != 2 || removed["token_usage"] != 1 || len(removed) != 3 {
		t.Fatalf("removed %+v", removed)
	}
	if same, r := WithoutSessions(env, nil); len(same.Actions) != 3 || len(r) != 0 {
		t.Fatal("an empty skip set must leave the envelope alone")
	}
}

func TestNodeVolume(t *testing.T) {
	cases := []struct {
		name          string
		used, batch   int64
		ok            bool
		wantRemaining int64
	}{
		{"fresh token", 0, 10, true, NodeRowCap},
		{"exactly fills the cap", NodeRowCap - 10, 10, true, 10},
		{"one row over", NodeRowCap - 10, 11, false, 10},
		{"already over (never negative)", NodeRowCap + 5, 0, true, 0},
		{"exhausted", NodeRowCap, 1, false, 0},
	}
	for _, tc := range cases {
		ok, rem := NodeVolume(tc.used, tc.batch, NodeRowCap)
		if ok != tc.ok || rem != tc.wantRemaining {
			t.Errorf("%s: (%v, %d), want (%v, %d)", tc.name, ok, rem, tc.ok, tc.wantRemaining)
		}
	}
}
