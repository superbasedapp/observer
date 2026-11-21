package cloudsession

import (
	"strings"
	"testing"
)

func mustAgent(t *testing.T, id string) Agent {
	t.Helper()
	a, err := AgentByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// initHookFile returns the hook file init writes for agent into repo.
func initHookFile(t *testing.T, agent string, repo memRepo, mutate func(*PlanOptions)) string {
	t.Helper()
	o := testOpts(agent)
	if mutate != nil {
		mutate(&o)
	}
	p, err := PlanInit(o, repo.read)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := HookFile(mustAgent(t, agent))
	for _, c := range p.Changes {
		if c.Path == f.Path {
			return c.After
		}
	}
	t.Fatalf("no %s in the plan", f.Path)
	return ""
}

// TestOwnedHookBlock: the digest covers exactly Observer's entries with
// their event and matcher, ignores the team's own entries and layout, and
// changes with any edit to an owned entry.
func TestOwnedHookBlock(t *testing.T) {
	for _, agent := range []string{"claude-code", "copilot"} {
		t.Run(agent, func(t *testing.T) {
			a := mustAgent(t, agent)
			base := initHookFile(t, agent, memRepo{}, nil)
			b, err := OwnedHookBlock(a, base, true)
			if err != nil {
				t.Fatal(err)
			}
			if want := len(plannedHooks(a, testOpts(agent))); !b.Present || !strings.HasPrefix(b.Digest, "sha256:") || b.Entries != want {
				t.Fatalf("block = %+v, want %d entries", b, want)
			}
			same := func(name, content string, want bool) {
				t.Helper()
				got, err := OwnedHookBlock(a, content, true)
				if err != nil {
					t.Fatal(err)
				}
				if (got.Digest == b.Digest) != want {
					t.Errorf("%s: digest equal = %v, want %v", name, got.Digest == b.Digest, want)
				}
			}
			// A layout-only change is the same block.
			same("compact layout", strings.Join(strings.Fields(base), " "), true)
			// Any change to an owned entry is not.
			same("destination changed", strings.Replace(base, "https://org.example.com", "https://evil.example", 1), false)
			same("one entry dropped", dropFirstOwned(t, base), false)
			same("timeout changed", strings.Replace(base, `60`, `61`, 1), false)
			if agent == "claude-code" {
				same("matcher changed", strings.Replace(base, `"matcher": "*"`, `"matcher": "Nothing"`, 1), false)
			}
			// Missing, unparsable and owner-less files have no block.
			for name, c := range map[string]string{"missing": "", "unparsable": "{", "no owner tag": strings.ReplaceAll(base, OwnerTag, "")} {
				got, err := OwnedHookBlock(a, c, name != "missing")
				if err != nil || got.Present {
					t.Errorf("%s: block = %+v, %v", name, got, err)
				}
			}
		})
	}
}

// TestOwnedHookBlockIgnoresTeamHooks: the team's own entries around
// Observer's do not change the digest.
func TestOwnedHookBlockIgnoresTeamHooks(t *testing.T) {
	a := mustAgent(t, "claude-code")
	alone := initHookFile(t, "claude-code", memRepo{}, nil)
	team := "{\n  \"permissions\": {\n    \"deny\": [\n      \"Read(./.env)\"\n    ]\n  },\n  \"hooks\": {\n    \"PostToolUse\": [\n      {\n        \"matcher\": \"Edit\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"make fmt\"\n          }\n        ]\n      }\n    ]\n  }\n}\n"
	withTeam := initHookFile(t, "claude-code", memRepo{ClaudeSettingsPath: team}, nil)
	b1, _ := OwnedHookBlock(a, alone, true)
	b2, _ := OwnedHookBlock(a, withTeam, true)
	if b1.Digest != b2.Digest {
		t.Error("the team's own hooks changed the owned-block digest")
	}
	edited := strings.Replace(withTeam, "make fmt", "rm -rf ~/.observer", 1)
	if b3, _ := OwnedHookBlock(a, edited, true); b3.Digest != b1.Digest {
		t.Error("a team entry edit changed the owned-block digest (it is out of scope by design)")
	}
}

func dropFirstOwned(t *testing.T, content string) string {
	t.Helper()
	root, err := parseJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	hooks := root.get("hooks")
	for _, arr := range hooks.vals {
		if len(arr.items) > 0 {
			arr.items = arr.items[1:]
			break
		}
	}
	return root.encode() + "\n"
}

// TestNeedsBaseline: a session keeps its baseline across resume and
// compaction; a new vendor session, another agent, or the first hook of an
// agent without a session reference takes a new one.
func TestNeedsBaseline(t *testing.T) {
	start, _ := TriggerSpecFor(TriggerStart)
	prompt, _ := TriggerSpecFor(TriggerPrompt)
	prev := &HookBaseline{Agent: "claude-code", VendorRef: "cse_a", Present: true, Digest: "sha256:x"}
	noRef := &HookBaseline{Agent: "copilot", Present: true, Digest: "sha256:x"}
	cases := []struct {
		name  string
		prev  *HookBaseline
		agent string
		ref   string
		spec  TriggerSpec
		want  bool
	}{
		{"none recorded", nil, "claude-code", "cse_a", prompt, true},
		{"same session, prompt", prev, "claude-code", "cse_a", prompt, false},
		{"same session, resumed start", prev, "claude-code", "cse_a", start, false},
		{"new session", prev, "claude-code", "cse_b", prompt, true},
		{"other agent", prev, "copilot", "cse_a", prompt, true},
		{"no reference, start", noRef, "copilot", "", start, true},
		{"no reference, prompt", noRef, "copilot", "", prompt, false},
	}
	for _, tc := range cases {
		if got := NeedsBaseline(tc.prev, tc.agent, tc.ref, tc.spec); got != tc.want {
			t.Errorf("%s: NeedsBaseline = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestCheckHookBlock: one case per guard rule, with the baseline taken from
// HEAD, or from the working tree only when told to trust it.
func TestCheckHookBlock(t *testing.T) {
	committed := HookBlock{Present: true, Entries: 3, Digest: "sha256:aaa"}
	edited := HookBlock{Present: true, Entries: 3, Digest: "sha256:bbb"}
	none := HookBlock{}
	cases := []struct {
		name         string
		head, work   HookBlock
		trust        bool
		wantSource   BaselineSource
		wantVerdict  GuardVerdict
		wantReason   CoverageReason
		wantDelivers bool
	}{
		{"committed and unchanged", committed, committed, false, BaselineHead, GuardVerified, "", true},
		{"edited after the baseline", committed, edited, false, BaselineHead, GuardChanged, ReasonHookBlockChanged, false},
		{"owned entries deleted", committed, none, false, BaselineHead, GuardChanged, ReasonHookBlockChanged, false},
		{"not committed", none, committed, false, BaselineHead, GuardUncommitted, ReasonHookBlockUncommitted, false},
		{"not committed, trusted for a manual test", none, committed, true, BaselineWorktree, GuardVerified, "", true},
		{"committed wins over the trust flag", committed, edited, true, BaselineHead, GuardChanged, ReasonHookBlockChanged, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := PlanBaseline("claude-code", "cse_a", tc.head, tc.work, tc.trust)
			if b.Source != tc.wantSource {
				t.Errorf("source = %s, want %s", b.Source, tc.wantSource)
			}
			v, r := CheckHookBlock(b, tc.work)
			if v != tc.wantVerdict || r != tc.wantReason {
				t.Errorf("verdict = %s/%q, want %s/%q", v, r, tc.wantVerdict, tc.wantReason)
			}
			if (v == GuardVerified) != tc.wantDelivers {
				t.Errorf("delivers = %v", v == GuardVerified)
			}
		})
	}
}
