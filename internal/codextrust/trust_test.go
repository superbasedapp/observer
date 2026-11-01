package codextrust

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// observerOwned is the ownership predicate the hook writer passes.
func observerOwned(c string) bool { return strings.Contains(c, " hook codex ") }

// trustHooksJSON renders a hooks.json with one Observer group per event
// (matcher "*", one command handler) after an optional user group.
func trustHooksJSON(events []string, userFirst bool, extra string) []byte {
	var b strings.Builder
	b.WriteString(`{"hooks":{`)
	for i, e := range events {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:[", e)
		if userFirst {
			b.WriteString(`{"matcher":"*","hooks":[{"type":"command","command":"my-own-hook"}]},`)
		}
		fmt.Fprintf(&b, `{"matcher":"*","hooks":[{"type":"command","command":%q%s}]}]`, fmt.Sprintf(liveCmd, e), extra)
	}
	b.WriteString("}}")
	return []byte(b.String())
}

// TestPlanTrustReproducesLiveCodexHashes: for Observer's six Codex events
// the ONE hash PlanTrust records equals the trusted_hash Codex itself
// recorded on a live node (liveVectors), and the key is
// "<KeyPath>:<snake event>:<group>:<handler>".
func TestPlanTrustReproducesLiveCodexHashes(t *testing.T) {
	var events []string
	want := map[string]string{}
	for _, v := range liveVectors {
		events = append(events, v.event)
		want[v.event] = v.hash
	}
	keyPath := `C:\Users\op\.codex\hooks.json`
	plan, skipped, err := PlanTrust(TrustInput{KeyPath: keyPath, HooksJSON: trustHooksJSON(events, true, ""), Owned: observerOwned})
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", skipped)
	}
	if len(plan) != len(events) {
		t.Fatalf("plan has %d records, want %d (the user's own group must never be planned): %+v", len(plan), len(events), plan)
	}
	for _, r := range plan {
		if normHash(r.Hash) != want[r.Event] {
			t.Errorf("%s: planned hash %s, live Codex recorded %s", r.Event, r.Hash, want[r.Event])
		}
		if !strings.HasPrefix(r.Hash, "sha256:") {
			t.Errorf("%s: hash %q lacks the sha256: prefix Codex writes", r.Event, r.Hash)
		}
		if wantKey := keyPath + ":" + CamelToSnake(r.Event) + ":1:0"; r.Key != wantKey {
			t.Errorf("%s: key %q, want %q", r.Event, r.Key, wantKey)
		}
	}
}

// TestPlanTrustRules pins PlanTrust's per-handler rule table, one case per
// row, and that a planned record always classifies as trusted afterwards.
func TestPlanTrustRules(t *testing.T) {
	keyPath := "/home/u/.codex/hooks.json"
	ev := "PreToolUse"
	key := keyPath + ":pre_tool_use:0:0"
	star := "*"
	cur := Hash("pre_tool_use", &star, fmt.Sprintf(liveCmd, ev), 600, false, nil)
	state := func(body string) []byte {
		return []byte(fmt.Sprintf("model = \"x\"\n[hooks.state.%s]\n%s\n", strconv.Quote(key), body))
	}
	cases := []struct {
		name     string
		hooks    []byte
		cfg      []byte
		wantPlan bool
		wantSkip string
	}{
		{name: "never trusted", hooks: trustHooksJSON([]string{ev}, false, ""), wantPlan: true},
		{name: "trusted for an older command", hooks: trustHooksJSON([]string{ev}, false, ""), cfg: state(`trusted_hash = "sha256:old"`), wantPlan: true},
		{name: "already trusted", hooks: trustHooksJSON([]string{ev}, false, ""), cfg: state("trusted_hash = " + strconv.Quote(cur))},
		{name: "turned off in /hooks", hooks: trustHooksJSON([]string{ev}, false, ""), cfg: state("enabled = false"), wantSkip: "turned off"},
		{name: "unhashed field", hooks: trustHooksJSON([]string{ev}, false, `,"commandWindows":"x"`), wantSkip: "does not hash exactly"},
		{name: "timeoutSec is not Codex's field", hooks: trustHooksJSON([]string{ev}, false, `,"timeoutSec":30`), wantSkip: "does not hash exactly"},
		{name: "async", hooks: trustHooksJSON([]string{ev}, false, `,"async":true`), wantSkip: "async"},
		{name: "unknown event", hooks: trustHooksJSON([]string{"Notification"}, false, ""), wantSkip: "vocabulary"},
		{name: "explicit timeout is hashed", hooks: trustHooksJSON([]string{ev}, false, `,"timeout":30`), wantPlan: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := TrustInput{KeyPath: keyPath, HooksJSON: c.hooks, ConfigTOML: c.cfg, Owned: observerOwned}
			plan, skipped, err := PlanTrust(in)
			if err != nil {
				t.Fatal(err)
			}
			if (len(plan) == 1) != c.wantPlan || len(plan) > 1 {
				t.Fatalf("plan = %+v, want planned %v", plan, c.wantPlan)
			}
			if c.wantSkip == "" && len(skipped) != 0 {
				t.Fatalf("skipped = %+v, want none", skipped)
			}
			if c.wantSkip != "" && (len(skipped) != 1 || !strings.Contains(skipped[0].Reason, c.wantSkip)) {
				t.Fatalf("skipped = %+v, want one mentioning %q", skipped, c.wantSkip)
			}
			if !c.wantPlan {
				return
			}
			// Writing the planned record makes Classify read the entry as
			// trusted and the hash as verified.
			cfg := fmt.Sprintf("[hooks.state.%s]\ntrusted_hash = %s\n", strconv.Quote(plan[0].Key), strconv.Quote(plan[0].Hash))
			rep, err := Classify(Input{HooksPath: keyPath, HooksJSON: c.hooks, ConfigTOML: []byte(cfg), Expected: []string{ev}, Owned: observerOwned})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Entries[0].State != StateTrusted || !rep.HashVerified {
				t.Errorf("after recording: state %s verified %v, want trusted and verified", rep.Entries[0].State, rep.HashVerified)
			}
		})
	}
}

// TestPlanTrustNeverPlansForeignHandlers: a hooks.json holding only the
// user's own hooks plans nothing, and OwnedTrustRecords lists only
// Observer's.
func TestPlanTrustNeverPlansForeignHandlers(t *testing.T) {
	hooks := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"my-own-hook"}]}]}}`)
	in := TrustInput{KeyPath: "/h/.codex/hooks.json", HooksJSON: hooks, Owned: observerOwned}
	plan, skipped, err := PlanTrust(in)
	if err != nil || len(plan) != 0 || len(skipped) != 0 {
		t.Fatalf("PlanTrust = %+v %+v %v, want nothing", plan, skipped, err)
	}
	if recs, err := OwnedTrustRecords(in); err != nil || len(recs) != 0 {
		t.Fatalf("OwnedTrustRecords = %+v %v, want none", recs, err)
	}
	if _, _, err := PlanTrust(TrustInput{HooksJSON: []byte("{"), Owned: observerOwned}); err == nil {
		t.Error("a malformed hooks.json planned without an error")
	}
	_, _, err = PlanTrust(TrustInput{HooksJSON: hooks, ConfigTOML: []byte("api_key = \"sk-SECRET\"\n[[["), Owned: observerOwned})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("a malformed config.toml: err = %v, want an error that does not quote the file", err)
	}
}

// TestPlanTrustShortTimeoutEvents: SessionEnd (codex-rs 0.157.1
// normalize_command_hook) defaults its timeout to 1 s, clamps it to 3 s and
// keeps the matcher; the planned hash follows those rules.
func TestPlanTrustShortTimeoutEvents(t *testing.T) {
	star := "*"
	cmd := fmt.Sprintf(liveCmd, "SessionEnd")
	for extra, timeout := range map[string]int64{"": 1, `,"timeout":2`: 2, `,"timeout":30`: 3} {
		plan, _, err := PlanTrust(TrustInput{KeyPath: "/h/.codex/hooks.json", HooksJSON: trustHooksJSON([]string{"SessionEnd"}, false, extra), Owned: observerOwned})
		if err != nil || len(plan) != 1 {
			t.Fatalf("%q: plan %+v err %v", extra, plan, err)
		}
		if want := Hash("session_end", &star, cmd, timeout, false, nil); plan[0].Hash != want {
			t.Errorf("%q: hash %s, want the %d s hash %s", extra, plan[0].Hash, timeout, want)
		}
	}
}
