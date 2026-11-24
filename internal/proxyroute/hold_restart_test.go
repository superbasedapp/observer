package proxyroute

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// hold_restart_test.go: the route hold across processes and against the
// settings beside a route (review of lane sr-restart, fixup/restart-hold).

// holdShapeEnv points every route-file relocation variable away, so a pinned
// test home resolves every row's file under itself.
func holdShapeEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "KIMI_CODE_HOME", "QWEN_HOME", "CRUSH_GLOBAL_CONFIG", "XDG_CONFIG_HOME"} {
		t.Setenv(k, "")
	}
}

// holdShapeFixtures routes one row of the route inspection table at holdPort
// the way `observer init` does, over a config the developer owns, and returns
// the config path. Every row must have one (TestHoldPutBackAcrossProcesses
// fails for a row without), so a new route row is covered here too.
var holdShapeFixtures = map[string]func(t *testing.T, home string) string{
	"claude-code": func(t *testing.T, home string) string {
		claude, _ := holdFixture(t, home, routeprov.WriterInit, "")
		return claude
	},
	// Codex with the developer's own provider selected before: the
	// put-back must switch model_provider back (Force) across processes.
	"codex": func(t *testing.T, home string) string {
		_, codex := holdFixture(t, home, routeprov.WriterInit, "")
		return codex
	},
	"kimi-code": func(t *testing.T, home string) string {
		path := writeKimiConfig(t, home, kimiBaseConfig)
		if res := holdReg(t, home, routeprov.WriterInit, "").RegisterKimiCode(); res.Error != nil || !res.Added {
			t.Fatalf("register kimi-code = %+v", res)
		}
		return path
	},
	// Qwen Code's removal sets model.baseUrl back to the default host
	// instead of deleting it (finding 1).
	"qwen-code": func(t *testing.T, home string) string {
		path := writeQwenConfig(t, home, qwenConfigWithProviders(qwenDefaultBaseURL))
		if res := holdReg(t, home, routeprov.WriterInit, "").RegisterQwenCode(); res.Error != nil || !res.Added {
			t.Fatalf("register qwen-code = %+v", res)
		}
		return path
	},
	"crush": func(t *testing.T, home string) string {
		path := writeCrushConfig(t, home, crushBaseConfig)
		if res := holdReg(t, home, routeprov.WriterInit, "").RegisterCrush(); res.Error != nil || !res.Added {
			t.Fatalf("register crush = %+v", res)
		}
		return path
	},
}

// holdOnly removes every route file but tool's, so a hold sees one route.
func holdOnly(t *testing.T, home, tool, keep string) {
	t.Helper()
	for _, ri := range routeInspectors() {
		if ri.tool == tool {
			continue
		}
		p, err := ri.path(inspectEnv{home: home, getenv: noEnv})
		if err == nil && p != keep {
			_ = os.Remove(p)
		}
	}
}

// unrelatedEdit changes a key no route writer owns, the way another program
// writing the file during the restart would.
func unrelatedEdit(t *testing.T, path string, f cfgfmt.Format) {
	t.Helper()
	doc, err := cfgfmt.Parse(f, holdRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Set(cfgfmt.Path{"zz_written_during_restart"}, "yes"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, doc.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestHoldPutBackAcrossProcesses: for every row of the route inspection
// table, a route `observer service stop` takes off is put back by a later
// process (`observer service start`, the daemon at its start), which has
// none of the first process's memory: byte for byte when nothing else wrote
// the file, and with the other program's change kept when something did.
// The provenance record is exactly the one before.
func TestHoldPutBackAcrossProcesses(t *testing.T) {
	holdShapeEnv(t)
	for _, ri := range routeInspectors() {
		fixture, ok := holdShapeFixtures[ri.tool]
		if !ok {
			t.Errorf("route row %s has no hold fixture; add one to holdShapeFixtures", ri.tool)
			continue
		}
		shape, _ := shapeFor(ri.tool)
		for _, changed := range []bool{false, true} {
			name := ri.tool + "/file unchanged"
			if changed {
				name = ri.tool + "/file changed meanwhile"
			}
			t.Run(name, func(t *testing.T) {
				home := t.TempDir()
				path := fixture(t, home)
				holdOnly(t, home, ri.tool, path)
				before := holdRead(t, path)
				first := holdReg(t, home, "", "")
				provBefore := holdRead(t, first.ProvenancePath())
				value, _, err := shape.read(path, nil)
				if err != nil || !IsObserverBaseURL(value) {
					t.Fatalf("fixture route = %q, %v", value, err)
				}

				hold, results, err := first.HoldRoutes()
				if err != nil {
					t.Fatal(err)
				}
				if r := holdResultFor(t, results, ri.tool); r.Action != HoldTakeOff || !r.TakenOff || r.Err != nil {
					t.Fatalf("hold = %+v", r)
				}
				if len(hold.Routes) != 1 {
					t.Fatalf("held %+v", hold.Routes)
				}
				if off, _, _ := shape.read(path, nil); IsObserverBaseURL(off) {
					t.Fatalf("the route is still on during the hold: %q", off)
				}
				if changed {
					unrelatedEdit(t, path, shape.keys(nil).format)
				}

				// The first process is gone (stop, then start).
				next := holdReg(t, home, "", "")
				pending, err := next.PendingRouteHold()
				if err != nil || len(pending.Routes) != 1 {
					t.Fatalf("pending = %+v, %v", pending, err)
				}
				rel := next.ReleaseRoutes(pending)
				if r := releaseResultFor(t, rel, ri.tool); r.Outcome != ReleaseRewritten || r.Err != nil {
					t.Fatalf("release = %+v", r)
				}
				if now, _, _ := shape.read(path, nil); now != value {
					t.Fatalf("route after the put-back = %q, want %q", now, value)
				}
				after := holdRead(t, path)
				if !changed && string(after) != string(before) {
					t.Fatalf("file after the put-back:\n%s\nwant\n%s", after, before)
				}
				if changed {
					if !strings.Contains(string(after), "zz_written_during_restart") {
						t.Fatal("the change made during the restart was lost")
					}
					if err := sameSettings(shape.keys(nil).format, removeUnrelated(t, after, shape.keys(nil).format), before); err != nil {
						t.Fatalf("a setting was lost or changed: %v\n%s", err, after)
					}
				}
				if string(holdRead(t, next.ProvenancePath())) != string(provBefore) {
					t.Fatal("the provenance record changed")
				}
				if _, err := os.Stat(next.RouteHoldPath()); !os.IsNotExist(err) {
					t.Fatal("journal left behind")
				}
			})
		}
	}
}

// removeUnrelated undoes unrelatedEdit on b (for the settings comparison).
func removeUnrelated(t *testing.T, b []byte, f cfgfmt.Format) []byte {
	t.Helper()
	doc, err := cfgfmt.Parse(f, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.Delete(cfgfmt.Path{"zz_written_during_restart"}); err != nil {
		t.Fatal(err)
	}
	return doc.Bytes()
}

// TestHoldJournalsWhatTheRemovalLeft: the Qwen Code entry records the
// default host its removal leaves and the route-key state, and the journal
// holds no whole-file digest.
func TestHoldJournalsWhatTheRemovalLeft(t *testing.T) {
	holdShapeEnv(t)
	home := t.TempDir()
	path := holdShapeFixtures["qwen-code"](t, home)
	holdOnly(t, home, "qwen-code", path)
	reg := holdReg(t, home, "", "")
	if _, _, err := reg.HoldRoutes(); err != nil {
		t.Fatal(err)
	}
	h, err := reg.PendingRouteHold()
	if err != nil || len(h.Routes) != 1 {
		t.Fatalf("journal = %+v, %v", h, err)
	}
	if h.Routes[0].Left != qwenDefaultBaseURL || h.Routes[0].LeftState == "" {
		t.Fatalf("entry = %+v", h.Routes[0])
	}
	if strings.Contains(string(holdRead(t, reg.RouteHoldPath())), "sha256") {
		t.Fatal("the journal holds a whole-file digest")
	}
}

// TestHoldKeepsACodexTableWithMoreThanTheWritersKeys (finding 2): Codex's
// remover deletes the whole [model_providers.openai-observer] table and its
// writer writes back only its four keys, so a table holding anything else of
// the developer's stays on and the file is not touched. The same table with
// only the writer's keys is taken off.
func TestHoldKeepsACodexTableWithMoreThanTheWritersKeys(t *testing.T) {
	holdShapeEnv(t)
	table := "model_provider = \"openai-observer\"\n\n[model_providers.openai-observer]\n" +
		"name = \"" + providerDisplayName + "\"\nbase_url = \"" + codexBaseURL(holdPort) + "\"\n"
	cases := []struct {
		name  string
		body  string
		taken bool
	}{
		{"only the writer's keys", table + "wire_api = \"responses\"\nrequires_openai_auth = true\n", true},
		{"the developer's own keys", table + "wire_api = \"responses\"\nrequires_openai_auth = true\nrequest_max_retries = 4\nhttp_headers = { \"X-Org\" = \"a\" }\n", false},
		{"a comment in the table", table + "# retries tuned for the VPN\nwire_api = \"responses\"\nrequires_openai_auth = true\n", false},
		{"another wire_api", table + "wire_api = \"chat\"\nrequires_openai_auth = true\n", false},
		{"another display name", strings.Replace(table, providerDisplayName, "My proxy", 1) + "wire_api = \"responses\"\nrequires_openai_auth = true\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".codex", "config.toml")
			provWrite(t, path, "model = \"gpt-x\"\n"+c.body)
			before := holdRead(t, path)
			reg := holdReg(t, home, "", "")
			hold, results, err := reg.HoldRoutes()
			if err != nil {
				t.Fatal(err)
			}
			r := holdResultFor(t, results, "codex")
			if c.taken {
				if r.Action != HoldTakeOff || !r.TakenOff {
					t.Fatalf("hold = %+v, want taken off", r)
				}
				rel := reg.ReleaseRoutes(hold)
				if rr := releaseResultFor(t, rel, "codex"); rr.Outcome != ReleaseRestored {
					t.Fatalf("release = %+v", rr)
				}
				return
			}
			if r.Action != HoldKeep || r.Reason != HoldReasonNotExact || r.TakenOff {
				t.Fatalf("hold = %+v, want keep/%s", r, HoldReasonNotExact)
			}
			if !hold.Empty() {
				t.Fatalf("held %+v", hold.Routes)
			}
			if string(holdRead(t, path)) != string(before) {
				t.Fatal("the Codex config changed")
			}
		})
	}
}

// TestReleaseNeverWritesOverAChangedRouteKey: a route key someone changed
// during the restart is left as it is: Qwen Code's base URL set to another
// host is "set meanwhile", Codex's model_provider switched to another
// provider is "changed meanwhile" (the route stays off), and neither file is
// written.
func TestReleaseNeverWritesOverAChangedRouteKey(t *testing.T) {
	holdShapeEnv(t)
	cases := []struct {
		tool   string
		key    cfgfmt.Path
		value  string
		format cfgfmt.Format
		want   ReleaseOutcome
	}{
		{"qwen-code", qwenBaseURLPath, "https://api.deepseek.com", cfgfmt.FormatJSON, ReleaseSetMeanwhile},
		{"codex", cfgfmt.Path{"model_provider"}, "someone-else", cfgfmt.FormatTOML, ReleaseChangedMeanwhile},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			home := t.TempDir()
			path := holdShapeFixtures[c.tool](t, home)
			holdOnly(t, home, c.tool, path)
			first := holdReg(t, home, "", "")
			if _, _, err := first.HoldRoutes(); err != nil {
				t.Fatal(err)
			}
			doc, err := cfgfmt.Parse(c.format, holdRead(t, path))
			if err != nil {
				t.Fatal(err)
			}
			if err := doc.Set(c.key, c.value); err != nil {
				t.Fatal(err)
			}
			provWrite(t, path, string(doc.Bytes()))
			mid := holdRead(t, path)
			next := holdReg(t, home, "", "")
			pending, _ := next.PendingRouteHold()
			if r := releaseResultFor(t, next.ReleaseRoutes(pending), c.tool); r.Outcome != c.want {
				t.Fatalf("release = %+v, want %s", r, c.want)
			}
			if string(holdRead(t, path)) != string(mid) {
				t.Fatal("the put-back wrote over a change made during the restart")
			}
		})
	}
}

// TestRouteHoldLockKeepsASecondRunOut (finding 5): while one run holds the
// route hold lock, another neither takes routes off nor puts them back, and
// the holder's own hold and release work.
func TestRouteHoldLockKeepsASecondRunOut(t *testing.T) {
	holdShapeEnv(t)
	home := t.TempDir()
	claude, _ := holdFixture(t, home, routeprov.WriterInit, "")
	first := holdReg(t, home, "", "")
	release, ok, err := first.LockRouteHold()
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	second := holdReg(t, home, "", "")
	before := holdRead(t, claude)
	if _, _, err := second.HoldRoutes(); !errors.Is(err, ErrRouteHoldBusy) {
		t.Fatalf("second hold err = %v, want busy", err)
	}
	if string(holdRead(t, claude)) != string(before) {
		t.Fatal("the second run took a route off")
	}
	if _, ok, _ := second.LockRouteHold(); ok {
		t.Fatal("the second run took the lock")
	}
	hold, _, err := first.HoldRoutes()
	if err != nil || hold.Empty() {
		t.Fatalf("holder's hold: %+v %v", hold, err)
	}
	if rel := second.ReleaseRoutes(hold); len(rel) != 1 || !errors.Is(rel[0].Err, ErrRouteHoldBusy) {
		t.Fatalf("second release = %+v", rel)
	}
	if _, _, err := second.ReleasePendingRoutes(); !errors.Is(err, ErrRouteHoldBusy) {
		t.Fatalf("second pending release err = %v", err)
	}
	for _, r := range first.ReleaseRoutes(hold) {
		if r.Outcome != ReleaseRestored {
			t.Fatalf("holder's release = %+v", r)
		}
	}
	release()
	if _, ok, err := second.LockRouteHold(); err != nil || !ok {
		t.Fatalf("lock after release: %v %v", ok, err)
	}
}

// TestReleasePendingRoutesForThisPortOnly: the daemon puts back a pending
// hold only for its own proxy port.
func TestReleasePendingRoutesForThisPortOnly(t *testing.T) {
	holdShapeEnv(t)
	home := t.TempDir()
	claude, _ := holdFixture(t, home, routeprov.WriterInit, "")
	before := holdRead(t, claude)
	if _, _, err := holdReg(t, home, "", "").HoldRoutes(); err != nil {
		t.Fatal(err)
	}
	other, err := NewRegistrar(RegisterOptions{ProxyPort: holdPort + 1, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	pending, results, err := other.ReleasePendingRoutes()
	if err != nil || len(results) != 0 || pending.Port != holdPort || len(pending.Routes) != 2 {
		t.Fatalf("other port: %+v %+v %v", pending, results, err)
	}
	_, results, err = holdReg(t, home, "", "").ReleasePendingRoutes()
	if err != nil || len(results) != 2 {
		t.Fatalf("own port: %+v %v", results, err)
	}
	if string(holdRead(t, claude)) != string(before) {
		t.Fatal("the claude settings did not come back")
	}
}
