package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// D-221 / T-327: the organization's fail_closed choice for an invalid user
// guard policy, as the hook applies it.

const (
	brokenUserPolicy = "[[override]]\nrule = \"R-110\"\ndecision = \"maybe\"\n"
	validUserPolicy  = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n"
	strictFallbacks  = "[fallbacks]\nuser_policy_invalid = \"fail_closed\"\n"
)

// TestHookUserPolicyGate is the hook-side matrix: the gate closes only when
// the plan fails closed (the family is enforced), the org chose fail_closed,
// the guard evaluates, and the user policy does NOT load right now. The
// block names the file and line in the dialect's own shape and spools one
// user_policy_fail_closed record; every other cell leaves the invocation
// untouched.
func TestHookUserPolicyGate(t *testing.T) {
	cases := []struct {
		name        string
		guard       string
		file        string // "" = absent
		failClosed  bool
		upfc        bool
		wantHandled bool
	}{
		{"enforced + fail_closed + broken file: closed", "enforce", brokenUserPolicy, true, true, true},
		{"enforced + fail_closed + valid file: open", "enforce", validUserPolicy, true, true, false},
		{"enforced + fail_closed + no file: open", "enforce", "", true, true, false},
		{"enforced + loud + broken file: open (T-323 behaviour)", "enforce", brokenUserPolicy, true, false, false},
		{"gate not enforced + fail_closed + broken file: open", "enforce", brokenUserPolicy, false, true, false},
		{"guard off + fail_closed + broken file: open", "off", brokenUserPolicy, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newPostureOrgNode(t, fmt.Sprintf("[guard]\nenabled = true\nmode = %q", tc.guard))
			if tc.file != "" {
				writeFileT(t, n.user, tc.file)
			}
			plan := provisionalHookFailurePlan("claude-code", "pre-tool", n.cp)
			plan.FailClosed, plan.UserPolicyFailClosed = tc.failClosed, tc.upfc
			h := newFailureHarness(t, plan)
			handled := hookUserPolicyGate(n.cp, strings.NewReader(`{"session_id":"sess-9","tool_name":"Bash"}`))
			if handled != tc.wantHandled {
				t.Fatalf("handled = %v, want %v (stdout %q stderr %q)", handled, tc.wantHandled, h.stdout.String(), h.stderr.String())
			}
			batch, err := guardposture.Drain(guardposture.SpoolPath(n.cp), 0)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.wantHandled {
				if h.stdout.Len() != 0 || batch != nil {
					t.Fatalf("an open cell replied %q / spooled %+v", h.stdout.String(), batch)
				}
				return
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: n.cp})
			if err != nil {
				t.Fatal(err)
			}
			st := guard.CheckUserPolicy(cfg.Guard, "", os.ReadFile)
			reason := guard.UserPolicyBlockReason(st)
			if !strings.Contains(reason, n.user+" line ") {
				t.Fatalf("reason %q does not name the file and line", reason)
			}
			var got, want any
			if err := json.Unmarshal(h.stdout.Bytes(), &got); err != nil {
				t.Fatalf("stdout is not one JSON reply: %v (%q)", err, h.stdout.String())
			}
			if err := json.Unmarshal([]byte(claudePreToolDeny(reason)), &want); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("stdout = %v\nwant %v", got, want)
			}
			if batch == nil || len(batch.Records) != 1 {
				t.Fatalf("spool = %+v, want one record", batch)
			}
			r := batch.Records[0]
			if r.Kind != guardposture.KindUserPolicyFailClosed || r.SessionID != "sess-9" || r.Cap != string(integration.HookCapToolGate) {
				t.Errorf("spool record = %+v", r)
			}
			v := hookFailureVerdict(r)
			if !strings.Contains(v.Verdict.Reason, "fail closed while the user guard policy does not load") || !v.Enforced {
				t.Errorf("drained verdict = %+v", v.Verdict)
			}
		})
	}
}

// TestHookUserPolicyGateExitCodeDialect pins the exit-code dialects: the
// prompt gate blocks with exit 2 and the reason on stderr.
func TestHookUserPolicyGateExitCodeDialect(t *testing.T) {
	n := newPostureOrgNode(t, "[guard]\nenabled = true\nmode = \"enforce\"")
	writeFileT(t, n.user, brokenUserPolicy)
	plan := provisionalHookFailurePlan("claude-code", "user-prompt-submit", n.cp)
	plan.FailClosed, plan.UserPolicyFailClosed = true, true
	h := newFailureHarness(t, plan)
	prevErr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	handled := hookUserPolicyGate(n.cp, strings.NewReader(`{"session_id":"s"}`))
	os.Stderr = prevErr
	_ = w.Close()
	buf := make([]byte, 4096)
	k, _ := r.Read(buf)
	if !handled || fmt.Sprint(h.exitCodes()) != "[2]" {
		t.Fatalf("handled=%v exits=%v, want true / [2]", handled, h.exitCodes())
	}
	if !strings.Contains(string(buf[:k]), n.user) {
		t.Errorf("stderr %q does not carry the reason", string(buf[:k]))
	}
}

// TestHookPlanReadsUserPolicyModeFromPosture: a VERIFIED daemon posture
// carries the mode to the plan, but only for a gate it closes.
func TestHookPlanReadsUserPolicyModeFromPosture(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.toml")
	writeFileT(t, cp, "")
	writePosture(t, cp, guardposture.Posture{
		Enforced: true, Source: guardposture.SourceOrg, GateCaps: []string{string(integration.HookCapToolGate)},
		UserPolicyFailClosed: true,
	})
	if p := resolveHookFailurePlan("claude-code", "pre-tool", cp); !p.FailClosed || !p.UserPolicyFailClosed {
		t.Errorf("tool gate plan = %+v, want fail-closed with the mode on", p)
	}
	if p := resolveHookFailurePlan("claude-code", "user-prompt-submit", cp); p.FailClosed || p.UserPolicyFailClosed {
		t.Errorf("prompt gate (not enforced) plan = %+v, want open", p)
	}
}

// TestDaemonAndHookAgreeOnUserPolicyMode pins D-194 for the new mode: the
// daemon's posture writer and the hook's fallback (posture ignored) derive it
// through the same guardGateEnforcement over the same inputs, so they agree
// on every node shape.
func TestDaemonAndHookAgreeOnUserPolicyMode(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, n postureOrgNode) (daemonStore bool)
		want  bool
	}{
		{"individual (unenrolled) node, bundle under the pin says fail_closed: loud", func(t *testing.T, n postureOrgNode) bool {
			pub := writeOrgBundle(t, n.bundle, strictFallbacks)
			seedPin(t, n.dbPath, pinOf(pub))
			return true
		}, false},
		// Review M2-14: with no store there is neither a key pin nor a
		// tenancy, so the bundle cannot be attributed to this node and the
		// org's mode is withheld on BOTH sides (one derivation, D-194); an
		// individual node must not get the org's fail_closed choice.
		{"tenancy unreadable (no DB), bundle says fail_closed: loud (not attributable)", func(t *testing.T, n postureOrgNode) bool {
			writeOrgBundle(t, n.bundle, strictFallbacks)
			if err := os.Mkdir(n.dbPath, 0o700); err != nil {
				t.Fatal(err)
			}
			return false
		}, false},
		{"tenancy unreadable, bundle has no table: loud", func(t *testing.T, n postureOrgNode) bool {
			writeOrgBundle(t, n.bundle, "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n")
			if err := os.Mkdir(n.dbPath, 0o700); err != nil {
				t.Fatal(err)
			}
			return false
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newPostureOrgNode(t, "[guard]\nenabled = true\nmode = \"enforce\"")
			withStore := tc.setup(t, n)
			cfg, err := config.Load(config.LoadOptions{GlobalPath: n.cp})
			if err != nil {
				t.Fatal(err)
			}
			// The daemon's side: its own guard, built by the daemon's builder
			// when it has a store, and the posture it would publish.
			var gd *guard.Guard
			if withStore {
				database, derr := dbtemplate.Open(context.Background(), db.Options{Path: n.dbPath})
				if derr != nil {
					t.Fatal(derr)
				}
				defer database.Close()
				gd = buildGuardForStore(context.Background(), cfg, store.New(database), slog.New(slog.DiscardHandler))
			} else {
				pin, managed, expected := nodeGuardPolicyInputs(context.Background(), nil, nil)
				gd, err = guard.New(guard.Options{Config: cfg.Guard, OrgKeyPinHash: pin, ManagedTenancy: managed, OrgBundleExpected: expected})
				if err != nil {
					t.Fatal(err)
				}
			}
			daemon := computeGuardPosture(cfg.Guard, gd, time.Now())
			// The hook's side: the daemon posture is ignored (forged), so the
			// hook derives the mode itself.
			forgeOpenPosture(t, n.cp)
			hookPlan := resolveHookFailurePlan("claude-code", "pre-tool", n.cp)
			if daemon.UserPolicyFailClosed != tc.want || hookPlan.UserPolicyFailClosed != tc.want {
				t.Errorf("daemon posture mode = %v, hook fallback mode = %v, want both %v", daemon.UserPolicyFailClosed, hookPlan.UserPolicyFailClosed, tc.want)
			}
		})
	}
}
