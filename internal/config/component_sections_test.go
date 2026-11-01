package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// withComponentGate installs g for one test and restores the previous gate.
func withComponentGate(t *testing.T, g ComponentGate) {
	t.Helper()
	prev := SetComponentGate(g)
	t.Cleanup(func() { SetComponentGate(prev) })
}

func loadBody(t *testing.T, body string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: NoGovernanceSidecar})
}

const badSandbox = "[terminal.sandbox]\nbackend = \"no-such-backend\"\n"

// TestLoadComponentAwareValidation walks the gate table: no gate is today's
// strict load; an active component keeps the strict load; an inactive one
// sets its bad section aside with one line and the section's defaults.
func TestLoadComponentAwareValidation(t *testing.T) {
	cases := []struct {
		name     string
		gate     ComponentGate
		wantErr  bool
		wantLine bool
	}{
		{"no gate registered: strict", nil, true, false},
		{"component active: strict", func(ComponentsConfig, string) bool { return true }, true, false},
		{"component inactive: set aside", func(ComponentsConfig, string) bool { return false }, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withComponentGate(t, tc.gate)
			cfg, err := loadBody(t, badSandbox)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if !strings.Contains(err.Error(), "terminal.sandbox.backend") {
					t.Fatalf("error does not name the key: %v", err)
				}
				return
			}
			if got := len(cfg.Inert) == 1; got != tc.wantLine {
				t.Fatalf("Inert = %q", cfg.Inert)
			}
			if !strings.Contains(cfg.Inert[0], "terminals.sandbox") || !strings.Contains(cfg.Inert[0], "no-such-backend") {
				t.Fatalf("the line must name the component and the value: %q", cfg.Inert[0])
			}
			if !reflect.DeepEqual(cfg.Terminal.Sandbox, Default().Terminal.Sandbox) {
				t.Fatalf("set-aside section must hold its defaults: %+v", cfg.Terminal.Sandbox)
			}
		})
	}
}

// TestComponentGateAskedOnlyForABadSection: a valid config resolves no
// component state (Load runs on every hook call).
func TestComponentGateAskedOnlyForABadSection(t *testing.T) {
	var asked []string
	withComponentGate(t, func(_ ComponentsConfig, id string) bool {
		asked = append(asked, id)
		return false
	})
	if _, err := loadBody(t, "[terminal.sandbox]\nhome_mode = \"readonly\"\n"); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 0 {
		t.Fatalf("gate asked for a valid config: %v", asked)
	}
	if _, err := loadBody(t, badSandbox); err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, ",") != "terminals.sandbox" {
		t.Fatalf("gate asked %v, want the owning component once", asked)
	}
}

// TestValidateStaysStrict: Validate checks every component section whatever
// the gate says, so a save path never writes a bad value.
func TestValidateStaysStrict(t *testing.T) {
	withComponentGate(t, func(ComponentsConfig, string) bool { return false })
	cfg := Default()
	cfg.Terminal.Sandbox.Backend = "no-such-backend"
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "terminal.sandbox.backend") {
		t.Fatalf("Validate must stay strict: %v", err)
	}
}

// TestSetAsideIsIdempotentOnAGovernedCopy: Load runs the pass on the file's
// copy and again on the governed copy (a governance pin is merged after the
// file, and a bad pinned value for an inactive component must not discard
// the whole overlay); the second pass over an already set-aside section adds
// no second line.
func TestSetAsideIsIdempotentOnAGovernedCopy(t *testing.T) {
	withComponentGate(t, func(ComponentsConfig, string) bool { return false })
	c := Default()
	c.Terminal.Sandbox.HomeMode = "nope"
	first := setAsideInactiveSections(&c)
	second := setAsideInactiveSections(&c)
	if len(first) != 1 || len(second) != 0 {
		t.Fatalf("first=%q second=%q", first, second)
	}
}

// TestComponentSectionRowsAreComplete pins each table row's shape: a
// component, a section owned once, a validator that accepts the defaults,
// and a reset.
func TestComponentSectionRowsAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range componentSections {
		if s.component == "" || s.section == "" || s.validate == nil || s.reset == nil {
			t.Fatalf("incomplete row: %+v", s)
		}
		if seen[s.section] {
			t.Errorf("section [%s] is owned twice", s.section)
		}
		seen[s.section] = true
		d := Default()
		if err := s.validate(&d); err != nil {
			t.Errorf("[%s]: defaults do not validate: %v", s.section, err)
		}
	}
	got := ComponentSections()
	if len(got) != len(componentSections) || got[0].Component != "terminals.sandbox" || got[0].Section != "terminal.sandbox" {
		t.Fatalf("ComponentSections = %+v", got)
	}
}
