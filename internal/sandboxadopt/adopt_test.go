package sandboxadopt

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// good is a container every refusal row lets through.
func good() Facts {
	return Facts{
		Active: true, RecordIntact: true, RecordOwned: true, PlanKept: true, LabelsMatch: true, Running: true,
		Engine:     EngineFacts{Engine: EnginePodman, Mode: ModeRootless, Conmon: true},
		ReadBackOK: true, ProtectedIntact: true, OfferedAt: t0, Now: t0.Add(time.Minute),
	}
}

// TestEngineTable has one case per engine mode the OCI rows know.
func TestEngineTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		f    EngineFacts
		want bool
	}{
		{"docker rootful live-restore", EngineFacts{Engine: EngineDocker, Mode: ModeRootful, LiveRestore: true}, true},
		{"docker rootful no live-restore", EngineFacts{Engine: EngineDocker, Mode: ModeRootful}, false},
		{"docker rootless", EngineFacts{Engine: EngineDocker, Mode: ModeRootless}, false},
		{"docker rootless live-restore set", EngineFacts{Engine: EngineDocker, Mode: ModeRootless, LiveRestore: true}, false},
		{"podman rootful conmon", EngineFacts{Engine: EnginePodman, Mode: ModeRootful, Conmon: true}, true},
		{"podman rootless conmon", EngineFacts{Engine: EnginePodman, Mode: ModeRootless, Conmon: true}, true},
		{"podman no conmon", EngineFacts{Engine: EnginePodman, Mode: ModeRootful}, false},
		{"unknown engine", EngineFacts{Engine: "nerdctl", Mode: ModeRootful, LiveRestore: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := EngineKeeps(c.f)
			if got != c.want || why == "" {
				t.Fatalf("EngineKeeps(%+v) = %v %q, want %v with a reason", c.f, got, why, c.want)
			}
		})
	}
}

// TestDecideTable has one case per row of the decision table, in order.
func TestDecideTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		edit   func(*Facts)
		action Action
		code   Code
		row    string
	}{
		{"component off", func(f *Facts) { f.Active = false }, ActionReap, CodeComponentInactive, "component"},
		{"record missing", func(f *Facts) { f.RecordIntact = false }, ActionReap, CodeRecordMissing, "record"},
		{"record tampered ownership", func(f *Facts) { f.RecordOwned = false }, ActionReap, CodeRecordNotOwned, "owner"},
		{"plan missing", func(f *Facts) { f.PlanKept = false }, ActionReap, CodePlanMissing, "plan"},
		{"labels", func(f *Facts) { f.LabelsMatch = false }, ActionReap, CodeNotThisInstall, "labels"},
		{"not running", func(f *Facts) { f.Running = false }, ActionReap, CodeNotRunning, "running"},
		{"cli run", func(f *Facts) { f.CLIRun = true }, ActionReap, CodeCLIRun, "cli-run"},
		{"docker rootless", func(f *Facts) { f.Engine = EngineFacts{Engine: EngineDocker, Mode: ModeRootless} }, ActionReap, CodeEngineEndsRun, "engine-mode"},
		{"docker no live-restore", func(f *Facts) { f.Engine = EngineFacts{Engine: EngineDocker, Mode: ModeRootful} }, ActionReap, CodeEngineEndsRun, "engine-mode"},
		{"read-back", func(f *Facts) { f.ReadBackOK, f.ReadBackReason = false, "network none: mode bridge FACT" }, ActionReap, CodeBuiltBelowPlan, "read-back"},
		{"protected", func(f *Facts) {
			f.ProtectedIntact, f.ProtectedReason = false, "the socket dir /tmp/observer-sbx-FACT is gone"
		}, ActionReap, CodeProtectedChanged, "protected"},
		{"declined", func(f *Facts) { f.Declined = true }, ActionReap, CodeDeclined, "declined"},
		{"update deferred past the bound", func(f *Facts) { f.UpdateDeferred, f.Now = true, t0.Add(time.Hour) }, ActionHold, CodeHeldForUpdate, "update-deferred"},
		{"bound expired", func(f *Facts) { f.Now = t0.Add(DefaultBound) }, ActionReap, CodeBoundExpired, "bound"},
		{"offered podman", func(*Facts) {}, ActionOffer, CodeOffered, RowOffer},
		{"offered docker live-restore", func(f *Facts) { f.Engine = EngineFacts{Engine: EngineDocker, Mode: ModeRootful, LiveRestore: true} }, ActionOffer, CodeOffered, RowOffer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := good()
			c.edit(&f)
			d := Decide(f)
			if d.Action != c.action || d.Code != c.code || d.Row != c.row || d.Reason == "" {
				t.Fatalf("Decide = %+v, want %s %s row %q with a reason", d, c.action, c.code, c.row)
			}
			// The logged and kept line never carries the run's facts
			// (audit FU10-A2); the full reason does, for the terminal.
			if d.Summary == "" || strings.Contains(d.Summary, "FACT") {
				t.Fatalf("Summary %q is empty or carries a run fact", d.Summary)
			}
			if strings.Contains(c.name, "read-back") || c.name == "protected" {
				if !strings.Contains(d.Reason, "FACT") {
					t.Fatalf("Reason %q lost the run's fact the terminal shows", d.Reason)
				}
			}
			if live := d.CountsLive(); live != (c.action != ActionReap) {
				t.Fatalf("CountsLive = %v for %s", live, c.action)
			}
		})
	}
}

// TestRowsCovered keeps the table and the cases in step: every row but the
// fall-through has a case above (one case per row).
func TestRowsCovered(t *testing.T) {
	t.Parallel()
	if len(rules) != 13 {
		t.Fatalf("the decision table has %d rows; add a case to TestDecideTable for the new one and update this count", len(rules))
	}
}

func TestOfferExpiry(t *testing.T) {
	t.Parallel()
	f := good()
	f.Bound = 3 * time.Minute
	d := Decide(f)
	if !d.Expires.Equal(t0.Add(3 * time.Minute)) {
		t.Fatalf("Expires = %v", d.Expires)
	}
	f.OfferedAt = time.Time{}
	if d := Decide(f); !d.Expires.Equal(f.Now.Add(3 * time.Minute)) {
		t.Fatalf("Expires from now = %v", d.Expires)
	}
}

func TestClampBound(t *testing.T) {
	t.Parallel()
	for in, want := range map[time.Duration]time.Duration{0: DefaultBound, time.Second: MinBound, 48 * time.Hour: MaxBound, 5 * time.Minute: 5 * time.Minute} {
		if got := ClampBound(in); got != want {
			t.Fatalf("ClampBound(%v) = %v, want %v", in, got, want)
		}
	}
}
