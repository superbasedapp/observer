package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// homeDisplay is p as a guard reason shows it: under the home directory as
// "~" plus the rest (on Windows the test temp folder is under the home, on
// Linux it is not), else p itself.
func homeDisplay(p string) string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return p
	}
	h = filepath.Clean(h)
	if len(p) > len(h) && strings.EqualFold(p[:len(h)], h) && os.IsPathSeparator(p[len(h)]) {
		return "~" + p[len(h):]
	}
	return p
}

// TestRecordUserPolicyInvalid pins the T-323 org event: a user policy
// the guard drops raises ONE guard_error flag with degraded_from
// "user_policy_invalid" per distinct file content, nothing for a valid
// file, and nothing while the guard is off.
func TestRecordUserPolicyInvalid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(dir, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)

	policyPath := filepath.Join(dir, "guard-policy.toml")
	g := config.GuardConfig{Enabled: true, Mode: "enforce"}
	g.Rules.UserPolicy = policyPath
	check := func(body string) guard.UserPolicyStatus {
		if err := os.WriteFile(policyPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return guard.CheckUserPolicy(g, dir, os.ReadFile)
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	broken := check("[[override]]\nrule = R-153\n")
	for i, want := range []bool{true, false} { // second tick: same content, de-duplicated
		wrote, err := recordUserPolicyInvalid(ctx, g, broken, st, now)
		if err != nil || wrote != want {
			t.Fatalf("tick %d: wrote=%v err=%v, want %v", i+1, wrote, err, want)
		}
	}
	// An edited, still-broken file is a new state: reported again.
	broken2 := check("[[override]]\nrule = \"R-999\"\n")
	if wrote, err := recordUserPolicyInvalid(ctx, g, broken2, st, now); err != nil || !wrote {
		t.Fatalf("edited broken file: wrote=%v err=%v, want a new event", wrote, err)
	}
	// Fixed: nothing.
	if wrote, _ := recordUserPolicyInvalid(ctx, g, check("[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\n"), st, now); wrote {
		t.Error("valid file raised an event")
	}
	// Guard off: a broken file is not in effect, no event.
	off := g
	off.Enabled = false
	if wrote, _ := recordUserPolicyInvalid(ctx, off, check("[[override]]\nrule = 1\nbogus = 2\n"), st, now); wrote {
		t.Error("guard off raised an event")
	}

	rows, err := st.GuardEventsAfter(ctx, 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("guard_events = %d (%v), want 2", len(rows), err)
	}
	for _, r := range rows {
		if r.RuleID != guard.GuardErrorRuleID || r.DegradedFrom != "user_policy_invalid" ||
			r.Decision != "flag" || r.EventKind != "config_change" || r.Severity != "high" || r.Enforced {
			t.Errorf("event row = %+v", r)
		}
		if !strings.Contains(r.Reason, homeDisplay(policyPath)) || !strings.Contains(r.Reason, "rules are OFF") {
			t.Errorf("reason %q does not name the file and the consequence", r.Reason)
		}
	}
	if !strings.Contains(rows[0].Reason, "line 2") {
		t.Errorf("first reason %q does not carry the line", rows[0].Reason)
	}
}

// TestGuardUserPolicyDoctorCheck pins the doctor row: an error (doctor
// exits non-zero) naming file, line and parse error while the guard
// runs; a warning while it is off; OK for absent or valid files.
func TestGuardUserPolicyDoctorCheck(t *testing.T) {
	t.Parallel()
	// The message names the file with the host separator (Windows 11 Pro rerun 2026-10-25, D5 group 4).
	path := filepath.FromSlash("/home/u/.observer/guard-policy.toml")
	files := map[string]string{
		"broken": "[[override]]\nrule = R-153\n",
		"valid":  "[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\n",
	}
	cases := []struct {
		name       string
		file       string // key into files; "" = absent
		enabled    bool
		want       diag.Status
		msg        []string
		failClosed bool
	}{
		{name: "absent", enabled: true, want: diag.StatusOK},
		{name: "valid", file: "valid", enabled: true, want: diag.StatusOK, msg: []string{"loads"}},
		{name: "broken, guard on", file: "broken", enabled: true, want: diag.StatusFail, msg: []string{path + " line 2", "parse", "rules are OFF"}},
		{name: "broken, guard off", file: "broken", want: diag.StatusWarn, msg: []string{path + " line 2", "guard is off"}},
		{name: "broken, org fail-closed", file: "broken", enabled: true, failClosed: true, want: diag.StatusFail, msg: []string{path + " line 2", "fail-closed", "BLOCKED"}},
		{name: "valid, org fail-closed", file: "valid", enabled: true, failClosed: true, want: diag.StatusOK, msg: []string{"loads"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Config{}
			cfg.Guard.Enabled, cfg.Guard.Mode = tc.enabled, "observe"
			cfg.Guard.Rules.UserPolicy = "~/.observer/guard-policy.toml"
			read := func(string) ([]byte, error) {
				if tc.file == "" {
					return nil, fs.ErrNotExist
				}
				return []byte(files[tc.file]), nil
			}
			c := guardUserPolicyDoctorCheck(cfg, "/home/u", read, tc.failClosed)
			if c.Name != "guard.user_policy" || c.Status != tc.want {
				t.Fatalf("check = %+v, want status %v", c, tc.want)
			}
			for _, m := range tc.msg {
				if !strings.Contains(c.Message, m) {
					t.Errorf("message %q missing %q", c.Message, m)
				}
			}
		})
	}
}
