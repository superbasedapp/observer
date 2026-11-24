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
