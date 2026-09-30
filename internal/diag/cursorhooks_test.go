package diag

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// cursorHooksFixtureEntry mirrors the unexported cursorHookEntry shape
// register.go writes ({"command": "..."}), duplicated here (rather than
// exported) since it's pure test-fixture JSON shape, not behavior.
type cursorHooksFixtureEntry struct {
	Command string `json:"command"`
}

// cursorHooksFixture builds a minimal hooks.json body with one event
// bound to cmd, leaving the rest of hook.CursorEvents() unregistered.
// Marshaled through encoding/json (rather than hand-built string
// concatenation) so a cmd containing quotes — like the orphaned curl
// hook's `-H "X-Observer-Token: ..."` — round-trips as valid JSON.
func cursorHooksFixture(event, cmd string) string {
	return mustMarshalJSON(map[string]any{
		"version": 1,
		"hooks": map[string][]cursorHooksFixtureEntry{
			event: {{Command: cmd}},
		},
	})
}

// cursorHooksFixtureAllCanonical builds a hooks.json body with every
// hook.CursorEvents() entry bound to its own canonical observer command.
func cursorHooksFixtureAllCanonical() string {
	hooks := map[string][]cursorHooksFixtureEntry{}
	for _, ev := range hook.CursorEvents() {
		hooks[ev] = []cursorHooksFixtureEntry{{Command: "/home/u/bin/observer hook cursor " + ev}}
	}
	return mustMarshalJSON(map[string]any{"version": 1, "hooks": hooks})
}

// mustMarshalJSON marshals v, panicking on error. Only ever called on
// fixture literals built from plain strings/maps/slices in this file, for
// which json.Marshal cannot fail — so a panic here would mean the fixture
// builder itself is broken, not a runtime condition tests need to assert
// on.
func mustMarshalJSON(v any) string {
	body, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(body)
}

// TestCheckCursorHooks is the table for the cursor.hooks doctor check.
// homeOverride is always passed non-empty (== homeDir) so
// crossmount.AutoDetectSuppressed keeps the check from ever touching a
// real foreign-OS home on the machine running the test — the check must
// be exercisable purely off the fixture homeDir it's given.
func TestCheckCursorHooks(t *testing.T) {
	const canonicalCmd = `/home/u/bin/observer hook cursor beforeSubmitPrompt --config /home/u/.observer/config.toml`
	const orphanedCmd = `curl.exe -sS -X POST -H "X-Observer-Token: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" ` +
		`--data-binary '@-' http://127.0.0.1:8081/api/cursor/hook/beforeSubmitPrompt`
	const foreignCmd = `powershell.exe -File C:\me\myhook.ps1`

	cases := []struct {
		name       string
		writeFile  bool
		body       string
		wantStatus Status
		wantMsg    string // substring
	}{
		{
			name:       "no hooks.json anywhere",
			writeFile:  false,
			wantStatus: StatusOK,
			wantMsg:    "cursor not installed",
		},
		{
			name:       "fully covered by canonical entries",
			writeFile:  true,
			body:       cursorHooksFixtureAllCanonical(),
			wantStatus: StatusOK,
			wantMsg:    "wired for every event",
		},
		{
			name:       "one event registered, rest missing => warn",
			writeFile:  true,
			body:       cursorHooksFixture("beforeSubmitPrompt", canonicalCmd),
			wantStatus: StatusWarn,
			wantMsg:    "no observer entry",
		},
		{
			name:       "orphaned observer HTTP hook => fail",
			writeFile:  true,
			body:       cursorHooksFixture("beforeSubmitPrompt", orphanedCmd),
			wantStatus: StatusFail,
			wantMsg:    "being dropped",
		},
		{
			name:       "genuine foreign hook alone is a coverage warning, not a fail",
			writeFile:  true,
			body:       cursorHooksFixture("beforeSubmitPrompt", foreignCmd),
			wantStatus: StatusWarn,
			wantMsg:    "no observer entry",
		},
		{
			name:       "corrupt JSON surfaces as a detail, not a crash",
			writeFile:  true,
			body:       `{not valid json`,
			wantStatus: StatusWarn,
			wantMsg:    "no observer entry",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			if tc.writeFile {
				mustWriteFile(t, filepath.Join(home, ".cursor", "hooks.json"), tc.body)
			}

			got := checkCursorHooks(home, home) // homeOverride == home: sandboxed, no cross-mount reads

			if got.Name != "cursor.hooks" {
				t.Errorf("Name = %q, want cursor.hooks", got.Name)
			}
			if got.Status != tc.wantStatus {
				t.Errorf("Status = %v, want %v (message: %q, details: %v)", got.Status, tc.wantStatus, got.Message, got.Details)
			}
			if !strings.Contains(got.Message, tc.wantMsg) {
				t.Errorf("Message = %q, want it to contain %q", got.Message, tc.wantMsg)
			}
		})
	}
}

// TestCheckCursorHooksFailMessageNamesTheFix pins the exact operator
// guidance a FAIL must carry: how to heal without manual intervention
// (restart) and the manual fallback (--force).
func TestCheckCursorHooksFailMessageNamesTheFix(t *testing.T) {
	home := t.TempDir()
	orphanedCmd := `curl.exe -X POST -H "X-Observer-Token: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" http://127.0.0.1:8081/api/cursor/hook/stop`
	mustWriteFile(t, filepath.Join(home, ".cursor", "hooks.json"), cursorHooksFixture("stop", orphanedCmd))

	got := checkCursorHooks(home, home)
	if got.Status != StatusFail {
		t.Fatalf("Status = %v, want StatusFail", got.Status)
	}
	allText := got.Message + " " + strings.Join(got.Details, " ")
	for _, want := range []string{"restart the daemon", "observer init --cursor --force"} {
		if !strings.Contains(allText, want) {
			t.Errorf("FAIL output missing expected fix guidance %q; got message=%q details=%v", want, got.Message, got.Details)
		}
	}
}

// TestCheckCursorHooksSandboxNeverReadsForeignHome pins the containment
// contract: a non-empty homeOverride must suppress cross-mount detection
// entirely (crossmount.AutoDetectSuppressed, the 2026-07-31 lesson), so a
// sandboxed empty home reports "cursor not installed" rather than
// spuriously picking up a real foreign-OS home on the machine running the
// test.
func TestCheckCursorHooksSandboxNeverReadsForeignHome(t *testing.T) {
	home := t.TempDir()
	got := checkCursorHooks(home, home)
	if got.Status != StatusOK || got.Message != "cursor not installed" {
		t.Errorf("sandboxed empty home: got Status=%v Message=%q, want OK/\"cursor not installed\"", got.Status, got.Message)
	}
}
