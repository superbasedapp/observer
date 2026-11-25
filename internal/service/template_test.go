package service

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// updateCriticalKeys are the [Service] directives that decide what systemd
// does when the update handshake's old daemon exits 0 with the new daemon
// running as its child (INFRA-01). An absent key is compared as systemd's
// default for it, so a template that spells out the default agrees with a
// unit that leaves it implicit.
var updateCriticalKeys = []struct{ key, systemdDefault string }{
	{"Type", "simple"},
	{"ExitType", "main"},
	{"KillMode", "control-group"},
	{"Restart", "no"},
	{"NotifyAccess", "none"},
	{"ExecStop", ""},
}

// serviceSection returns the last value of each key in a unit's [Service]
// section (systemd lets a later assignment override an earlier one).
func serviceSection(t *testing.T, unit string) map[string]string {
	t.Helper()
	out := map[string]string{}
	inService := false
	sc := bufio.NewScanner(strings.NewReader(unit))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "["):
			inService = line == "[Service]"
			continue
		}
		if !inService {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRenderUnitAgreesWithReferenceTemplate pins INFRA-01's drift: the
// documentation template deploy/supervisor/observer.service and the unit
// `observer service install` writes must say the same thing about every
// directive that decides the update handover. RenderUnit is the one owner;
// the template is rendered for a systemd new enough for every row (the
// template's own documented floor).
func TestRenderUnitAgreesWithReferenceTemplate(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	tmplPath := filepath.Join(filepath.Dir(file), "..", "..", "deploy", "supervisor", "observer.service")
	raw, err := os.ReadFile(tmplPath) //nolint:gosec // a repo file at a fixed relative path
	if err != nil {
		t.Fatalf("read reference template: %v", err)
	}
	tmpl := serviceSection(t, string(raw))
	got := serviceSection(t, RenderUnit(UnitOptions{
		ExecPath: "/home/dev/.local/bin/observer", Scope: ScopeUser, SystemdVersion: MinExitTypeCgroupVersion,
	}))
	for _, k := range updateCriticalKeys {
		want, ok := tmpl[k.key]
		if !ok {
			want = k.systemdDefault
		}
		have, ok := got[k.key]
		if !ok {
			have = k.systemdDefault
		}
		if have != want {
			t.Errorf("%s: RenderUnit writes %q, deploy/supervisor/observer.service says %q", k.key, have, want)
		}
	}
}

// unitDirectives returns every directive of a unit, by section and key, with
// each key's values in file order (Environment= and other list keys repeat).
func unitDirectives(t *testing.T, unit string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(unit))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "["):
			section = line
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			key := section + strings.TrimSpace(k)
			out[key] = append(out[key], strings.TrimSpace(v))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// referenceUnitExceptions are the only directives on which the unit
// `observer service install` writes may differ from the reference unit, each
// with the reason. Every other directive in either file must be in both, with
// the same values.
var referenceUnitExceptions = map[string]string{
	// Per install: the value is the install's own, the key is in both.
	"[Unit]Description":    "names what this node's `observer start` runs (T-744)",
	"[Service]ExecStart":   "the installed binary's own path and the install's --config/--port",
	"[Service]Environment": "the install's merged PATH and extra Environment=, which a hand-copied template cannot know",
	// In the reference only. A dashboard terminal is a child of the daemon,
	// so these would reach the developer's own shells and AI tools.
	"[Service]NoNewPrivileges": "would stop sudo (and every setuid program) inside dashboard terminals",
	"[Service]PrivateTmp":      "would give dashboard terminals a /tmp apart from the developer's own shells, and a user unit cannot start without unprivileged user namespaces",
}

// TestRenderUnitMatchesReferenceUnit pins INFRA-01 for the whole unit, not
// only the update-critical keys: the unit `observer service install` writes
// and deploy/supervisor/observer.service carry the same directives with the
// same values, except the reasoned rows of referenceUnitExceptions. A
// directive added to one and not the other fails here until it is added to
// the other or given a reason.
func TestRenderUnitMatchesReferenceUnit(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "supervisor", "observer.service")) //nolint:gosec // a repo file at a fixed relative path
	if err != nil {
		t.Fatalf("read reference unit: %v", err)
	}
	ref := unitDirectives(t, string(raw))
	got := unitDirectives(t, RenderUnit(UnitOptions{
		ExecPath: "/home/dev/.local/bin/observer", Scope: ScopeUser, SystemdVersion: MinExitTypeCgroupVersion,
	}))
	keys := map[string]bool{}
	for k := range ref {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	for k := range keys {
		r, inRef := ref[k]
		g, inGot := got[k]
		if reason, ok := referenceUnitExceptions[k]; ok {
			if !inRef && !inGot {
				t.Errorf("exception %s (%s) names a directive neither unit has; drop it", k, reason)
			}
			continue
		}
		switch {
		case !inRef:
			t.Errorf("%s=%q: RenderUnit writes it, deploy/supervisor/observer.service does not", k, g)
		case !inGot:
			t.Errorf("%s=%q: deploy/supervisor/observer.service has it, RenderUnit does not write it", k, r)
		case strings.Join(r, "\n") != strings.Join(g, "\n"):
			t.Errorf("%s: RenderUnit writes %q, deploy/supervisor/observer.service says %q", k, g, r)
		}
	}
	// The per-install rows are in both files; only their values differ.
	for _, k := range []string{"[Unit]Description", "[Service]ExecStart"} {
		if _, ok := ref[k]; !ok {
			t.Errorf("%s: missing from deploy/supervisor/observer.service", k)
		}
		if _, ok := got[k]; !ok {
			t.Errorf("%s: missing from the unit RenderUnit writes", k)
		}
	}
}
