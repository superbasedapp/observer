package kirocrew_test

// This file is the DOUBLE-COUNT rule's end-to-end pin. It is an external
// test package (kirocrew_test) so it can import internal/adapter/kirocli
// alongside internal/adapter/kirocrew without either package depending on
// the other — the two adapters share no code, only a grounded fact.
//
// The fixtures under testdata/kirocrew/ are BOTH halves of ONE real
// conversation captured 2026-09-03: the Kiro Crew desktop chat transcript
// AND the kiro-cli agent session Crew drove for it. Ingesting both must
// produce exactly ONE session with no duplicated turns.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/kirocli"
	"github.com/marmutapp/superbased-observer/internal/adapter/kirocrew"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	fixtureSlot    = "dashboard_chat-2-1700000002"
	fixtureTwinSID = "sess0001-0000-4000-8000-000000000001"
	plainSID       = "sess0003-0000-4000-8000-000000000003"
)

// stageBothStores lays the fixtures out the way a real host holds them:
//
//	<home>/.kiro/crew/session_map.json
//	<home>/.kiro/crew/sessions/<slot>.jsonl        (Crew's chat transcript)
//	<home>/.kiro/sessions/cli/<sid>.{json,jsonl}   (the driven kiro-cli session)
//
// It returns the two watch roots.
func stageBothStores(t *testing.T) (crewRoot, cliRoot string) {
	t.Helper()
	home := t.TempDir()
	crewRoot = filepath.Join(home, ".kiro", "crew", "sessions")
	cliRoot = filepath.Join(home, ".kiro", "sessions")

	copyIn := func(src, dst string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read fixture %s: %v", src, err)
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	td := func(rel ...string) string {
		return filepath.Join(append([]string{"..", "..", "..", "testdata", "kirocrew"}, rel...)...)
	}

	copyIn(td("crew", "session_map.json"), filepath.Join(home, ".kiro", "crew", "session_map.json"))
	copyIn(td("crew", "sessions", fixtureSlot+".jsonl"), filepath.Join(crewRoot, fixtureSlot+".jsonl"))
	for _, ext := range []string{".json", ".jsonl"} {
		copyIn(td("kiro-cli", fixtureTwinSID+ext), filepath.Join(cliRoot, "cli", fixtureTwinSID+ext))
	}
	copyIn(td("kiro-cli", plainSID+".json"), filepath.Join(cliRoot, "cli", plainSID+".json"))
	return crewRoot, cliRoot
}

// parseAll walks every file under root and hands the ones the adapter
// claims to ParseSessionFile, accumulating the results — a miniature of
// what the watcher does.
func parseAll(t *testing.T, a adapter.Adapter, root string) adapter.ParseResult {
	t.Helper()
	var out adapter.ParseResult
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !a.IsSessionFile(path) {
			return err
		}
		res, perr := a.ParseSessionFile(context.Background(), path, 0)
		if perr != nil {
			t.Fatalf("%s.ParseSessionFile(%s): %v", a.Name(), path, perr)
		}
		out.ToolEvents = append(out.ToolEvents, res.ToolEvents...)
		out.TokenEvents = append(out.TokenEvents, res.TokenEvents...)
		out.SessionSurfaces = append(out.SessionSurfaces, res.SessionSurfaces...)
		out.Warnings = append(out.Warnings, res.Warnings...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCrewDrivenSessionIsCapturedExactlyOnce is the ticket's dedupe pin:
// ingest BOTH stores, assert exactly one session and no duplicated turns.
func TestCrewDrivenSessionIsCapturedExactlyOnce(t *testing.T) {
	crewRoot, cliRoot := stageBothStores(t)

	crew := parseAll(t, kirocrew.NewWithOptions(nil, crewRoot), crewRoot)
	cli := parseAll(t, kirocli.NewWithOptions(nil, cliRoot), cliRoot)

	// (a) The Crew adapter contributes NOTHING for a chat kiro-cli owns.
	if len(crew.ToolEvents) != 0 || len(crew.TokenEvents) != 0 {
		t.Errorf("kiro-crew emitted %d events / %d tokens for a kiro-cli-owned chat, want 0/0",
			len(crew.ToolEvents), len(crew.TokenEvents))
	}

	// (b) Exactly ONE session id across both adapters for this
	// conversation — the driven kiro-cli session, never the chat slot.
	sessions := map[string]string{} // sessionID -> tool
	for _, e := range append(append([]models.ToolEvent{}, crew.ToolEvents...), cli.ToolEvents...) {
		sessions[e.SessionID] = e.Tool
	}
	if got, ok := sessions[fixtureTwinSID]; !ok || got != models.ToolKiroCLI {
		t.Errorf("session %s owned by %q, want it present and owned by %q", fixtureTwinSID, got, models.ToolKiroCLI)
	}
	if _, dup := sessions[fixtureSlot]; dup {
		t.Errorf("the Crew chat slot %q also became a session — the conversation is captured twice", fixtureSlot)
	}
	if len(sessions) != 1 {
		t.Errorf("sessions = %v, want exactly one (the plain-CLI fixture is a .json state sidecar with no stream, so it yields no rows)", sessions)
	}

	// (c) No duplicated turns. The store's uniqueness pair is
	// (source_file, source_event_id), so that is the key to collapse on.
	// Note kiro-cli's flat bundle deliberately fires on BOTH the `.json`
	// and `.jsonl` triggers and emits under the canonical `.jsonl`
	// SourceFile either way — a documented cross-trigger repeat the store
	// upsert absorbs, NOT a double-count. What must never happen is the
	// SAME turn arriving under two different keys, which is what a second
	// session would produce.
	byKey := map[[2]string]string{} // key -> tool that emitted it
	for _, e := range crew.ToolEvents {
		byKey[[2]string{e.SourceFile, e.SourceEventID}] = e.Tool
	}
	crewKeys := len(byKey)
	for _, e := range cli.ToolEvents {
		k := [2]string{e.SourceFile, e.SourceEventID}
		if prev, ok := byKey[k]; ok && prev != e.Tool {
			t.Errorf("event key %v claimed by both %q and %q", k, prev, e.Tool)
		}
		byKey[k] = e.Tool
	}
	if crewKeys != 0 {
		t.Errorf("kiro-crew contributed %d distinct event keys, want 0", crewKeys)
	}
	// 1 prompt + 10 assistant steps + 9 tool calls = the whole
	// conversation, once. The 9 is the SAME nine tool calls the Crew
	// transcript logs (byte-identical ids — see
	// TestToolCallIdsAreSharedAcrossBothStores); they land exactly once,
	// under kiro-cli.
	if len(byKey) != 20 {
		t.Errorf("distinct persisted rows = %d, want 20 (1 prompt + 10 assistant steps + 9 tool calls)", len(byKey))
	}
	var tools int
	for _, e := range cli.ToolEvents {
		switch e.ActionType {
		case models.ActionReadFile, models.ActionWriteFile, models.ActionEditFile, models.ActionRunCommand:
			tools++
		}
	}
	// Both triggers fire, so the raw count is 2x the 9 distinct calls.
	if tools != 18 {
		t.Errorf("kiro-cli tool actions = %d, want 18 (9 distinct x 2 bundle triggers)", tools)
	}
}

// TestCrewDrivenSessionIsStampedDesktop pins the kiro-cli HALF of the
// rule: the driven session carries the desktop/kiro-crew surface (from
// its own agent_name), while a plain terminal session stays cli/kiro-cli.
func TestCrewDrivenSessionIsStampedDesktop(t *testing.T) {
	_, cliRoot := stageBothStores(t)
	cli := parseAll(t, kirocli.NewWithOptions(nil, cliRoot), cliRoot)

	got := map[string]models.SessionSurface{}
	for _, s := range cli.SessionSurfaces {
		got[s.SessionID] = s
	}
	crewDriven, ok := got[fixtureTwinSID]
	if !ok {
		t.Fatalf("no surface stamped for the Crew-driven session; got %v", got)
	}
	if crewDriven.Surface != models.SurfaceDesktop || crewDriven.SurfaceHost != "kiro-crew" {
		t.Errorf("Crew-driven surface = %s/%s, want desktop/kiro-crew",
			crewDriven.Surface, crewDriven.SurfaceHost)
	}
}

// TestToolCallIdsAreSharedAcrossBothStores documents, as an executable
// fact, WHY the double-count rule is needed at all: the two stores use
// byte-identical tool-call ids for the same call, so without the rule the
// same nine tool calls would land twice under two tool identities.
func TestToolCallIdsAreSharedAcrossBothStores(t *testing.T) {
	crewBody, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kirocrew", "crew", "sessions", fixtureSlot+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cliBody, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kirocrew", "kiro-cli", fixtureTwinSID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	crewText, cliText := string(crewBody), string(cliBody)

	// The nine anonymized ids keep the vendor's "tooluse_" prefix.
	var shared int
	for i := 1; i <= 9; i++ {
		id := "tooluse_0" + string(rune('0'+i)) + "AAAAAAAAAAAAAAAAAAAA"
		inCrew := strings.Contains(crewText, id)
		inCLI := strings.Contains(cliText, id)
		if inCrew && inCLI {
			shared++
			continue
		}
		t.Errorf("tool-call id %s: crew=%v cli=%v, want present in both", id, inCrew, inCLI)
	}
	if shared != 9 {
		t.Errorf("shared tool-call ids = %d, want 9", shared)
	}
}
