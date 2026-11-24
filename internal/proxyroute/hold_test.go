package proxyroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

const holdPort = 18655

// holdReg is a registrar for home on holdPort with writer w.
func holdReg(t *testing.T, home string, w routeprov.Writer, token string) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: holdPort, HomeDir: home, Writer: w, ClientToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func holdRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// holdFixture writes a Claude Code settings.json and a Codex config.toml the
// developer owns, then routes both through `observer init`'s writer.
func holdFixture(t *testing.T, home string, w routeprov.Writer, token string) (claude, codex string) {
	t.Helper()
	claude = filepath.Join(home, ".claude", "settings.json")
	codex = filepath.Join(home, ".codex", "config.toml")
	provWrite(t, claude, `{"env":{"KEEP_ME":"1"},"hooks":{"PreToolUse":[]},"model":"x"}`)
	provWrite(t, codex, "# my codex config\nmodel = \"gpt-x\" # keep this comment\nmodel_provider = \"mine\"\n\n[model_providers.mine]\nname = \"mine\"\nbase_url = \"https://example.invalid/v1\"\n")
	reg := holdReg(t, home, w, token)
	if res := reg.RegisterClaudeCode(); res.Error != nil || !res.Added {
		t.Fatalf("register claude = %+v", res)
	}
	// The developer's own provider is selected: init switches it with
	// --force and records it as the prior provider.
	forced, err := NewRegistrar(RegisterOptions{ProxyPort: holdPort, HomeDir: home, Writer: w, ClientToken: token, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if res := forced.RegisterCodex(); res.Error != nil || !res.Added {
		t.Fatalf("register codex = %+v", res)
	}
	return claude, codex
}

func holdResultFor(t *testing.T, results []HoldResult, tool string) HoldResult {
	t.Helper()
	for _, r := range results {
		if r.Tool == tool {
			return r
		}
	}
	t.Fatalf("no %s result in %+v", tool, results)
	return HoldResult{}
}

func releaseResultFor(t *testing.T, results []ReleaseResult, tool string) ReleaseResult {
	t.Helper()
	for _, r := range results {
		if r.Tool == tool {
			return r
		}
	}
	t.Fatalf("no %s release result in %+v", tool, results)
	return ReleaseResult{}
}

// TestDecideHoldRows: one case per holdRules row.
func TestDecideHoldRows(t *testing.T) {
	ours := RouteStatus{State: RouteOurs, Port: holdPort}
	cases := []struct {
		name   string
		in     holdInput
		action HoldAction
		reason HoldReason
	}{
		{"no route", holdInput{Status: RouteStatus{State: RouteAbsent}, Port: holdPort}, HoldSkip, HoldReasonNotThisProxy},
		{"another port", holdInput{Status: RouteStatus{State: RouteOurs, Port: 8820}, Port: holdPort, Removable: true, WriterAgrees: true}, HoldSkip, HoldReasonNotThisProxy},
		{"inactive provider", holdInput{Status: RouteStatus{State: RouteInactiveProvider, Port: holdPort}, Port: holdPort}, HoldSkip, HoldReasonNotThisProxy},
		{"another host", holdInput{Status: RouteStatus{State: RouteDrifted}, Port: holdPort}, HoldSkip, HoldReasonNotThisProxy},
		{"organization route", holdInput{Status: ours, Port: holdPort, OrgOwned: true, Removable: true, WriterAgrees: true}, HoldKeep, HoldReasonOrgRoute},
		{"provider lane", holdInput{Status: RouteStatus{State: RouteOurs, Port: holdPort, Lane: true}, Port: holdPort, Removable: true, WriterAgrees: true}, HoldKeep, HoldReasonProviderLane},
		{"no remover", holdInput{Status: ours, Port: holdPort, WriterAgrees: true}, HoldKeep, HoldReasonNoRemover},
		{"not the writer's value", holdInput{Status: ours, Port: holdPort, Removable: true}, HoldKeep, HoldReasonNotWriterValue},
		{"put-back not exact", holdInput{Status: ours, Port: holdPort, Removable: true, WriterAgrees: true}, HoldKeep, HoldReasonNotExact},
		{"take off", holdInput{Status: ours, Port: holdPort, Removable: true, WriterAgrees: true, Exact: true}, HoldTakeOff, HoldReasonRouted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, r := decideHold(c.in)
			if a != c.action || r != c.reason {
				t.Fatalf("decideHold = %s/%s, want %s/%s", a, r, c.action, c.reason)
			}
		})
	}
}

// TestHoldRoutesTakesOffAndRestoresExactly: the routes this proxy serves are
// taken off with the Leave removers and come back byte for byte, and the
// journal never holds file bytes.
func TestHoldRoutesTakesOffAndRestoresExactly(t *testing.T) {
	home := t.TempDir()
	claude, codex := holdFixture(t, home, routeprov.WriterInit, "")
	reg := holdReg(t, home, "", "")
	claudeBefore, codexBefore := holdRead(t, claude), holdRead(t, codex)
	provBefore := holdRead(t, reg.ProvenancePath())

	hold, results, err := reg.HoldRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"claude-code", "codex"} {
		if r := holdResultFor(t, results, tool); r.Action != HoldTakeOff || !r.TakenOff || r.Err != nil {
			t.Fatalf("%s hold = %+v", tool, r)
		}
	}
	if len(hold.Routes) != 2 {
		t.Fatalf("held %d routes, want 2", len(hold.Routes))
	}
	if strings.Contains(string(holdRead(t, claude)), "ANTHROPIC_BASE_URL") {
		t.Fatal("claude route still set during the hold")
	}
	if !strings.Contains(string(holdRead(t, claude)), "KEEP_ME") {
		t.Fatal("the hold removed more than the route")
	}
	if strings.Contains(string(holdRead(t, codex)), ProviderName) {
		t.Fatal("codex route still set during the hold")
	}
	if !strings.Contains(string(holdRead(t, codex)), `model_provider = "mine"`) {
		t.Fatal("codex prior provider not selected during the hold")
	}
	journal := holdRead(t, reg.RouteHoldPath())
	if strings.Contains(string(journal), "KEEP_ME") || strings.Contains(string(journal), "keep this comment") {
		t.Fatal("the journal holds file bytes")
	}
	if fi, err := os.Stat(reg.RouteHoldPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}

	rel := reg.ReleaseRoutes(hold)
	for _, tool := range []string{"claude-code", "codex"} {
		if r := releaseResultFor(t, rel, tool); r.Outcome != ReleaseRestored || r.Err != nil {
			t.Fatalf("%s release = %+v", tool, r)
		}
	}
	if string(holdRead(t, claude)) != string(claudeBefore) || string(holdRead(t, codex)) != string(codexBefore) {
		t.Fatal("the files did not come back byte for byte")
	}
	if string(holdRead(t, reg.ProvenancePath())) != string(provBefore) {
		t.Fatal("the provenance file changed")
	}
	if _, err := os.Stat(reg.RouteHoldPath()); !os.IsNotExist(err) {
		t.Fatalf("journal left behind after a full release: %v", err)
	}
}

// TestHoldRoutesLeavesOtherRoutes: a route at another port, a route to
// another host, an organization's route and a hand-written spelling of this
// proxy's route are never taken off.
func TestHoldRoutesLeavesOtherRoutes(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, home string) string
		reported bool
		reason   HoldReason
	}{
		{
			name: "another observer port",
			setup: func(t *testing.T, home string) string {
				p := filepath.Join(home, ".claude", "settings.json")
				provWrite(t, p, `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9999"}}`)
				return p
			},
		},
		{
			name: "another host",
			setup: func(t *testing.T, home string) string {
				p := filepath.Join(home, ".claude", "settings.json")
				provWrite(t, p, `{"env":{"ANTHROPIC_BASE_URL":"https://gateway.example.invalid"}}`)
				return p
			},
		},
		{
			name: "the organization wrote it",
			setup: func(t *testing.T, home string) string {
				p := filepath.Join(home, ".claude", "settings.json")
				provWrite(t, p, `{}`)
				holdReg(t, home, routeprov.WriterEnrolment, "").RegisterClaudeCode()
				return p
			},
			reported: true, reason: HoldReasonOrgRoute,
		},
		{
			name: "a hand-written spelling",
			setup: func(t *testing.T, home string) string {
				p := filepath.Join(home, ".claude", "settings.json")
				provWrite(t, p, `{"env":{"ANTHROPIC_BASE_URL":"http://localhost:18655"}}`)
				return p
			},
			reported: true, reason: HoldReasonNotWriterValue,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			path := c.setup(t, home)
			before := holdRead(t, path)
			reg := holdReg(t, home, "", "")
			hold, results, err := reg.HoldRoutes()
			if err != nil {
				t.Fatal(err)
			}
			if !hold.Empty() {
				t.Fatalf("held %+v", hold.Routes)
			}
			if c.reported {
				if r := holdResultFor(t, results, "claude-code"); r.Action != HoldKeep || r.Reason != c.reason || r.TakenOff {
					t.Fatalf("result = %+v, want keep/%s", r, c.reason)
				}
			} else if len(results) != 0 {
				t.Fatalf("results = %+v, want none", results)
			}
			if string(holdRead(t, path)) != string(before) {
				t.Fatal("a route the hold must leave was changed")
			}
			if _, err := os.Stat(reg.RouteHoldPath()); !os.IsNotExist(err) {
				t.Fatal("a journal was written for an empty hold")
			}
		})
	}
}

// TestHoldRoutesDryRunWritesNothing: a dry-run registrar decides only.
func TestHoldRoutesDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	claude, _ := holdFixture(t, home, routeprov.WriterInit, "")
	before := holdRead(t, claude)
	dry, err := NewRegistrar(RegisterOptions{ProxyPort: holdPort, HomeDir: home, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	hold, results, err := dry.HoldRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if r := holdResultFor(t, results, "claude-code"); r.Action != HoldTakeOff || r.TakenOff {
		t.Fatalf("dry run result = %+v", r)
	}
	if !hold.Empty() || string(holdRead(t, claude)) != string(before) {
		t.Fatal("the dry run changed something")
	}
	if _, err := os.Stat(dry.RouteHoldPath()); !os.IsNotExist(err) {
		t.Fatal("the dry run wrote a journal")
	}
}

// TestReleaseRewritesWhenTheFileChanged: when another writer changed the file
// during the restart, the row's writer writes the same route again, the
// other change stays, and the provenance record is exactly the one before.
func TestReleaseRewritesWhenTheFileChanged(t *testing.T) {
	home := t.TempDir()
	claude, _ := holdFixture(t, home, routeprov.WriterInit, "")
	reg := holdReg(t, home, "", "")
	provBefore := holdRead(t, reg.ProvenancePath())
	hold, _, err := reg.HoldRoutes()
	if err != nil {
		t.Fatal(err)
	}
	// The relaunched daemon's hook pass (or the developer) edits the file.
	provWrite(t, claude, `{"env":{"KEEP_ME":"1"},"hooks":{"PreToolUse":[]},"model":"y"}`)

	rel := reg.ReleaseRoutes(hold)
	if r := releaseResultFor(t, rel, "claude-code"); r.Outcome != ReleaseRewritten || r.Err != nil {
		t.Fatalf("claude release = %+v", r)
	}
	if r := releaseResultFor(t, rel, "codex"); r.Outcome != ReleaseRestored {
		t.Fatalf("codex release = %+v", r)
	}
	env := provClaudeEnv(t, home)
	if env["ANTHROPIC_BASE_URL"] != claudeBaseURL(holdPort) || env[ClaudeGatewayHintEnv] != "1" || env["KEEP_ME"] != "1" {
		t.Fatalf("env after release = %v", env)
	}
	if !strings.Contains(string(holdRead(t, claude)), `"y"`) {
		t.Fatal("the change made during the restart was lost")
	}
	if string(holdRead(t, reg.ProvenancePath())) != string(provBefore) {
		t.Fatalf("provenance changed:\n%s\nwant\n%s", holdRead(t, reg.ProvenancePath()), provBefore)
	}
}

// TestReleaseLeavesARouteSetMeanwhile and a config file that is gone.
func TestReleaseLeavesARouteSetMeanwhile(t *testing.T) {
	home := t.TempDir()
	claude, codex := holdFixture(t, home, routeprov.WriterInit, "")
	reg := holdReg(t, home, "", "")
	hold, _, err := reg.HoldRoutes()
	if err != nil {
		t.Fatal(err)
	}
	provWrite(t, claude, `{"env":{"ANTHROPIC_BASE_URL":"https://mine.example.invalid"}}`)
	if err := os.Remove(codex); err != nil {
		t.Fatal(err)
	}
	rel := reg.ReleaseRoutes(hold)
	if r := releaseResultFor(t, rel, "claude-code"); r.Outcome != ReleaseSetMeanwhile {
		t.Fatalf("claude release = %+v", r)
	}
	if r := releaseResultFor(t, rel, "codex"); r.Outcome != ReleaseConfigGone {
		t.Fatalf("codex release = %+v", r)
	}
	if got := provClaudeEnv(t, home)["ANTHROPIC_BASE_URL"]; got != "https://mine.example.invalid" {
		t.Fatalf("a route set during the restart was overwritten: %v", got)
	}
	if _, err := os.Stat(codex); !os.IsNotExist(err) {
		t.Fatal("release created a config file that was gone")
	}
}

// TestInterruptedHoldIsPutBackByTheNextRun: a run killed after the removal
// leaves the journal; the next hold carries those routes (without taking
// anything again) and its release puts them back with the writer and the
// records as they were.
func TestInterruptedHoldIsPutBackByTheNextRun(t *testing.T) {
	home := t.TempDir()
	token := strings.Repeat("ab", proxyauth.TokenLen/2)
	claude, codex := holdFixture(t, home, routeprov.WriterInit, token)
	first := holdReg(t, home, "", token)
	claudeBefore := holdRead(t, claude)
	provBefore := holdRead(t, first.ProvenancePath())
	if _, _, err := first.HoldRoutes(); err != nil {
		t.Fatal(err)
	}
	// The run dies here: no release, the in-memory bytes are lost.

	next := holdReg(t, home, "", token)
	pending, err := next.PendingRouteHold()
	if err != nil || len(pending.Routes) != 2 {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	hold, results, err := next.HoldRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("the next hold took routes again: %+v", results)
	}
	if len(hold.Routes) != 2 {
		t.Fatalf("the next hold dropped the interrupted routes: %+v", hold.Routes)
	}
	rel := next.ReleaseRoutes(hold)
	for _, tool := range []string{"claude-code", "codex"} {
		if r := releaseResultFor(t, rel, tool); r.Outcome != ReleaseRewritten || r.Err != nil {
			t.Fatalf("%s release = %+v", tool, r)
		}
	}
	if string(holdRead(t, claude)) != string(claudeBefore) {
		t.Fatalf("claude settings:\n%s\nwant\n%s", holdRead(t, claude), claudeBefore)
	}
	if !strings.Contains(string(holdRead(t, codex)), "/t/"+token) {
		t.Fatal("codex route not put back in the client token form")
	}
	if string(holdRead(t, next.ProvenancePath())) != string(provBefore) {
		t.Fatalf("provenance after recovery:\n%s\nwant\n%s", holdRead(t, next.ProvenancePath()), provBefore)
	}
	if _, err := os.Stat(next.RouteHoldPath()); !os.IsNotExist(err) {
		t.Fatal("journal left behind after recovery")
	}
}

// TestHoldRoutesRefusesAnotherPortsPendingHold: an interrupted hold for
// another proxy port is never mixed into this one.
func TestHoldRoutesRefusesAnotherPortsPendingHold(t *testing.T) {
	home := t.TempDir()
	holdFixture(t, home, routeprov.WriterInit, "")
	if _, _, err := holdReg(t, home, "", "").HoldRoutes(); err != nil {
		t.Fatal(err)
	}
	other, err := NewRegistrar(RegisterOptions{ProxyPort: holdPort + 1, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.HoldRoutes(); err == nil {
		t.Fatal("a hold for another port was accepted")
	}
}

// TestHoldRoutesUnreadableJournalRemovesNothing: a journal that does not
// parse is an error and no route is touched.
func TestHoldRoutesUnreadableJournalRemovesNothing(t *testing.T) {
	home := t.TempDir()
	claude, _ := holdFixture(t, home, routeprov.WriterInit, "")
	reg := holdReg(t, home, "", "")
	provWrite(t, reg.RouteHoldPath(), "{not json")
	before := holdRead(t, claude)
	if _, _, err := reg.HoldRoutes(); err == nil {
		t.Fatal("an unreadable journal was accepted")
	}
	if string(holdRead(t, claude)) != string(before) {
		t.Fatal("a route was removed despite the unreadable journal")
	}
}
