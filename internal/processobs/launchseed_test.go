package processobs

import (
	"testing"
	"time"
)

// launchSeedTestSession builds a CrossOSSessionRef with sensible defaults.
func launchSeedTestSession(id, tool, root string, started time.Time) CrossOSSessionRef {
	return CrossOSSessionRef{SessionID: id, Tool: tool, ProjectRoot: root, StartedAt: started}
}

func TestMatchLaunchSeeds_BasicMatch(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "opencode", "/proj", spawn.Add(30*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, nil)
	if got[100] != "sess-1" {
		t.Fatalf("MatchLaunchSeeds = %v, want pid 100 → sess-1", got)
	}
}

func TestMatchLaunchSeeds_ToolMismatch(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "claude-code", "/proj", spawn.Add(30*time.Second)),
	}
	if got := MatchLaunchSeeds(seeds, sessions, nil, nil); len(got) != 0 {
		t.Fatalf("MatchLaunchSeeds = %v, want no match on tool mismatch", got)
	}
}

func TestMatchLaunchSeeds_CaseInsensitiveTool(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "OpenCode", CWD: "/proj", StartedAt: spawn}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "opencode", "/proj", spawn.Add(30*time.Second)),
	}
	if got := MatchLaunchSeeds(seeds, sessions, nil, nil); got[100] != "sess-1" {
		t.Fatalf("MatchLaunchSeeds = %v, want case-insensitive tool match", got)
	}
}

func TestMatchLaunchSeeds_CWDMismatch(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj-a", StartedAt: spawn}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "opencode", "/proj-b", spawn.Add(30*time.Second)),
	}
	if got := MatchLaunchSeeds(seeds, sessions, nil, nil); len(got) != 0 {
		t.Fatalf("MatchLaunchSeeds = %v, want no match on cwd mismatch", got)
	}
}

func TestMatchLaunchSeeds_EmptySeedCWDMatchesAnyRoot(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "", StartedAt: spawn}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "opencode", "/anywhere", spawn.Add(30*time.Second)),
	}
	if got := MatchLaunchSeeds(seeds, sessions, nil, nil); got[100] != "sess-1" {
		t.Fatalf("MatchLaunchSeeds = %v, want empty seed cwd to match any root", got)
	}
}

func TestMatchLaunchSeeds_WindowBounds(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn}}

	tooEarly := launchSeedTestSession("sess-early", "opencode", "/proj", spawn.Add(-LaunchSeedBackSkew-time.Second))
	tooLate := launchSeedTestSession("sess-late", "opencode", "/proj", spawn.Add(LaunchSeedForwardWindow+time.Second))
	inWindow := launchSeedTestSession("sess-in", "opencode", "/proj", spawn.Add(LaunchSeedForwardWindow))

	if got := MatchLaunchSeeds(seeds, []CrossOSSessionRef{tooEarly}, nil, nil); len(got) != 0 {
		t.Fatalf("matched session older than back-skew: %v", got)
	}
	if got := MatchLaunchSeeds(seeds, []CrossOSSessionRef{tooLate}, nil, nil); len(got) != 0 {
		t.Fatalf("matched session past forward window: %v", got)
	}
	if got := MatchLaunchSeeds(seeds, []CrossOSSessionRef{inWindow}, nil, nil); got[100] != "sess-in" {
		t.Fatalf("MatchLaunchSeeds = %v, want boundary-inclusive forward match", got)
	}
}

func TestMatchLaunchSeeds_TwoSimultaneousSessionsNotCrossAttributed(t *testing.T) {
	t.Parallel()
	// Two launches in the SAME project seconds apart, two sessions: the
	// injective pairing must give each seed its own session — never both
	// seeds anchoring to one session.
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{
		{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn},
		{PID: 200, Tool: "opencode", CWD: "/proj", StartedAt: spawn.Add(5 * time.Second)},
	}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-a", "opencode", "/proj", spawn.Add(10*time.Second)),
		launchSeedTestSession("sess-b", "opencode", "/proj", spawn.Add(15*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, nil)
	if len(got) != 2 {
		t.Fatalf("MatchLaunchSeeds = %v, want two injective pairs", got)
	}
	if got[100] != "sess-a" || got[200] != "sess-b" {
		t.Fatalf("MatchLaunchSeeds = %v, want oldest seed → earliest session pairing", got)
	}
}

func TestMatchLaunchSeeds_ClaimedPIDSkipped(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "opencode", "/proj", spawn.Add(30*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, map[int]bool{100: true}, nil)
	if len(got) != 0 {
		t.Fatalf("MatchLaunchSeeds = %v, want claimed pid skipped", got)
	}
}

func TestMatchLaunchSeeds_SingleSessionNotDoubleClaimed(t *testing.T) {
	t.Parallel()
	// One session, two matching seeds (e.g. a relaunch recycled nothing but
	// both pids are pending): only ONE seed may win the session.
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{
		{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn},
		{PID: 200, Tool: "opencode", CWD: "/proj", StartedAt: spawn},
	}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "opencode", "/proj", spawn.Add(30*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, nil)
	if len(got) != 1 {
		t.Fatalf("MatchLaunchSeeds = %v, want exactly one claim on a single session", got)
	}
}

// TestMatchLaunchSeeds_CWDShapeFolding pins the B2 barrier for the launch-seed
// pairing rule: the launcher records the cwd the OS handed it, while the
// session's project root arrives in whatever shape the ADAPTER recorded. The
// two spell the same directory; a verbatim comparison silently drops the match
// and the launch falls back to lazy correlation. Table-driven so a new shape is
// one row (CLAUDE.md rule 5).
func TestMatchLaunchSeeds_CWDShapeFolding(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name        string
		seedCWD     string
		projectRoot string
		want        bool
	}{
		{"identical", "/proj", "/proj", true},
		{"trailing separator on the session root", "/proj", "/proj/", true},
		{"trailing separator on the seed", "/proj/", "/proj", true},
		{"windows separators vs forward slashes", `C:\proj`, "C:/proj", true},
		{"windows drive-letter case", `C:\proj`, `c:\proj`, true},
		{"vs code URI fsPath leading slash", `C:\proj`, "/c:/proj", true},
		{"genuinely different directories", "/proj", "/other", false},
		{"empty seed cwd stays a wildcard", "", "/anywhere", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: tc.seedCWD, StartedAt: spawn}}
			sessions := []CrossOSSessionRef{
				launchSeedTestSession("sess-1", "opencode", tc.projectRoot, spawn.Add(30*time.Second)),
			}
			got := MatchLaunchSeeds(seeds, sessions, nil, nil)
			if matched := got[100] == "sess-1"; matched != tc.want {
				t.Fatalf("MatchLaunchSeeds(seed cwd %q, root %q) = %v, want matched=%v",
					tc.seedCWD, tc.projectRoot, got, tc.want)
			}
		})
	}
}

// TestMatchLaunchSeeds_FoldedCWDStillDiscriminatesProjects guards the other
// direction: folding must not turn the project-root guard into a wildcard.
// Two concurrent same-tool launches in different projects must pair to their
// OWN sessions, never cross.
func TestMatchLaunchSeeds_FoldedCWDStillDiscriminatesProjects(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{
		{PID: 100, Tool: "opencode", CWD: "/a/proj/", StartedAt: spawn},
		{PID: 200, Tool: "opencode", CWD: "/b/proj", StartedAt: spawn.Add(time.Second)},
	}
	sessions := []CrossOSSessionRef{
		// The B session starts FIRST, so a wildcard rule would hand it to the
		// A seed (earliest-started unclaimed session wins).
		launchSeedTestSession("sess-b", "opencode", "/b/proj/", spawn.Add(10*time.Second)),
		launchSeedTestSession("sess-a", "opencode", "/a/proj", spawn.Add(20*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, nil)
	if got[100] != "sess-a" || got[200] != "sess-b" {
		t.Fatalf("MatchLaunchSeeds = %v, want pid 100→sess-a and pid 200→sess-b (no cross-project bind)", got)
	}
}

// --- task 9f: deterministic run binding (migration 091) -------------------

// TestMatchLaunchSeeds_RunIDBeatsHeuristic is the 9f regression. The heuristic
// would confidently pair this seed with the WRONG session — same tool, same
// project root, inside the window — and the run binding must overrule it. A
// session_pid_bridge row is HIGH-confidence identity every reader trusts, so
// "confidently wrong" is the worst outcome available here.
func TestMatchLaunchSeeds_RunIDBeatsHeuristic(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn, RunID: "run-A"}}
	sessions := []CrossOSSessionRef{
		// The heuristic's pick: earliest-started matching session.
		launchSeedTestSession("sess-heuristic", "opencode", "/proj", spawn.Add(10*time.Second)),
		launchSeedTestSession("sess-truth", "opencode", "/proj", spawn.Add(40*time.Second)),
	}
	runSessions := map[string]string{"run-A": "sess-truth"}

	got := MatchLaunchSeeds(seeds, sessions, nil, runSessions)
	if got[100] != "sess-truth" {
		t.Fatalf("MatchLaunchSeeds = %v, want pid 100 → sess-truth (the run binding, not the heuristic's earlier session)", got)
	}
	// Prove the heuristic really would have chosen otherwise, so this test
	// cannot pass for the wrong reason if the fixture drifts.
	if bare := MatchLaunchSeeds(seeds, sessions, nil, nil); bare[100] != "sess-heuristic" {
		t.Fatalf("without a run binding the heuristic should pick sess-heuristic, got %v — the fixture no longer proves precedence", bare)
	}
}

// TestMatchLaunchSeeds_RunIDIgnoresCwdAndWindow pins that a run binding needs
// no corroboration: the daemon minted the id before spawning this exact child,
// so a cwd that differs from the tool's reported project root, a tool-name
// mismatch, and a session created outside the forward window can each only
// REJECT a correct answer.
func TestMatchLaunchSeeds_RunIDIgnoresCwdAndWindow(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/launched/from/here", StartedAt: spawn, RunID: "run-A"}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-truth", "some-other-tool", "/a/totally/different/root", spawn.Add(3*time.Hour)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, map[string]string{"run-A": "sess-truth"})
	if got[100] != "sess-truth" {
		t.Fatalf("MatchLaunchSeeds = %v, want pid 100 → sess-truth: a known identity needs no cwd/tool/time corroboration", got)
	}
}

// TestMatchLaunchSeeds_HeuristicSurvivesForUnboundSeeds pins that 091 REMOVES
// nothing: a bare `observer <tool>` in the operator's own shell has no run id,
// and must still pair exactly as it did before.
func TestMatchLaunchSeeds_HeuristicSurvivesForUnboundSeeds(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{
		{PID: 100, Tool: "opencode", CWD: "/proj-a", StartedAt: spawn, RunID: "run-A"},
		{PID: 200, Tool: "opencode", CWD: "/proj-b", StartedAt: spawn}, // no run: bare shell
	}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-a", "opencode", "/proj-a", spawn.Add(20*time.Second)),
		launchSeedTestSession("sess-b", "opencode", "/proj-b", spawn.Add(25*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, map[string]string{"run-A": "sess-a"})
	if got[100] != "sess-a" {
		t.Errorf("pid 100 = %q, want sess-a (run-bound)", got[100])
	}
	if got[200] != "sess-b" {
		t.Errorf("pid 200 = %q, want sess-b (heuristic still serves an unbound seed)", got[200])
	}
}

// TestMatchLaunchSeeds_RunIDClaimsSessionBeforeHeuristic pins the ORDERING.
// Both seeds are heuristically eligible for sess-x; the run-bound one owns it,
// and the other must be left unmatched rather than stealing it. Running the
// passes the other way round would let a cwd/timing coincidence outrank a
// known fact.
func TestMatchLaunchSeeds_RunIDClaimsSessionBeforeHeuristic(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{
		// The heuristic walks seeds oldest-first, so this one would win sess-x.
		{PID: 200, Tool: "opencode", CWD: "/proj", StartedAt: spawn},
		{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn.Add(time.Second), RunID: "run-A"},
	}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-x", "opencode", "/proj", spawn.Add(20*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, map[string]string{"run-A": "sess-x"})
	if got[100] != "sess-x" {
		t.Errorf("pid 100 = %q, want sess-x — the run binding must claim it first", got[100])
	}
	if got[200] != "" {
		t.Errorf("pid 200 = %q, want unmatched: the session is already accounted for by a run", got[200])
	}
}

// TestMatchLaunchSeeds_RunIDInjectiveAcrossNestedLaunches covers the one way a
// run id can legitimately appear on two seeds: a nested `observer <tool>` typed
// inside a dashboard terminal inherits the parent's environment. Only ONE may
// bind, and it must be the OLDEST — the launcher the daemon actually spawned
// for the run. (The launcher-side guard in cmd/observer/launchseed.go normally
// stops the nested seed from carrying the id at all; this is the matcher's own
// belt-and-braces, and it is what keeps the rule injective on any platform.)
func TestMatchLaunchSeeds_RunIDInjectiveAcrossNestedLaunches(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{
		{PID: 300, Tool: "opencode", CWD: "/proj", StartedAt: spawn.Add(5 * time.Minute), RunID: "run-A"}, // nested, later
		{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn, RunID: "run-A"},                      // the daemon's own child
	}
	got := MatchLaunchSeeds(seeds, nil, nil, map[string]string{"run-A": "sess-truth"})
	if got[100] != "sess-truth" {
		t.Errorf("pid 100 = %q, want sess-truth (oldest seed for the run wins)", got[100])
	}
	if got[300] != "" {
		t.Errorf("pid 300 = %q, want unmatched: one run binds one pid", got[300])
	}
}

// TestMatchLaunchSeeds_RunIDRespectsClaimed pins that an existing
// session_pid_bridge row (hook ancestor-walk) still wins over a run binding —
// the pre-existing ownership rule is unchanged by 091.
func TestMatchLaunchSeeds_RunIDRespectsClaimed(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn, RunID: "run-A"}}
	got := MatchLaunchSeeds(seeds, nil, map[int]bool{100: true}, map[string]string{"run-A": "sess-truth"})
	if len(got) != 0 {
		t.Fatalf("MatchLaunchSeeds = %v, want empty: an already-claimed pid is never re-matched", got)
	}
}

// TestMatchLaunchSeeds_UnknownRunFallsBackToHeuristic pins the honest-absence
// case: a run whose correlation is missing or below the confidence gate
// contributes nothing, and its seed is served by the heuristic rather than
// being dropped.
func TestMatchLaunchSeeds_UnknownRunFallsBackToHeuristic(t *testing.T) {
	t.Parallel()
	spawn := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	seeds := []LaunchSeed{{PID: 100, Tool: "opencode", CWD: "/proj", StartedAt: spawn, RunID: "run-unresolved"}}
	sessions := []CrossOSSessionRef{
		launchSeedTestSession("sess-1", "opencode", "/proj", spawn.Add(20*time.Second)),
	}
	got := MatchLaunchSeeds(seeds, sessions, nil, map[string]string{"run-other": "sess-elsewhere"})
	if got[100] != "sess-1" {
		t.Fatalf("MatchLaunchSeeds = %v, want pid 100 → sess-1 via the heuristic fallback", got)
	}
}
