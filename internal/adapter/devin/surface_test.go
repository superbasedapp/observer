package devin

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestSurfaceForSession(t *testing.T) {
	cases := []struct {
		name string
		row  sessionRow
		want models.SessionSurface
		ok   bool
	}{
		{
			name: "desktop tab id stamps ide/devin-desktop",
			row: sessionRow{ID: "amber-lantern", Metadata: `{"total_credit_cost":0,` +
				`"client_meta":{"cognition.ai/requestingTabId":"new-1700000000000-tab0"}}`},
			want: models.SessionSurface{SessionID: "amber-lantern", Surface: models.SurfaceIDE, SurfaceHost: "devin-desktop"},
			ok:   true,
		},
		{
			// The honesty rule: a session with no client marker is NOT
			// assumed to be a terminal session — on Windows the desktop
			// and the standalone CLI share one store.
			name: "no client_meta yields no stamp",
			row:  sessionRow{ID: "tidy-marmot", Metadata: `{"total_credit_cost":0,"total_acu_cost":0.0}`},
		},
		{
			name: "unknown client_meta key yields no stamp",
			row:  sessionRow{ID: "s", Metadata: `{"client_meta":{"cognition.ai/somethingElse":"x"}}`},
		},
		{
			name: "store predating the metadata column yields no stamp",
			row:  sessionRow{ID: "s", Metadata: ""},
		},
		{
			name: "malformed metadata yields no stamp",
			row:  sessionRow{ID: "s", Metadata: "{not json"},
		},
		{
			name: "empty session id yields no stamp",
			row:  sessionRow{Metadata: `{"client_meta":{"cognition.ai/requestingTabId":"t"}}`},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := surfaceForSession(c.row)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, c.ok, got)
			}
			if got != c.want {
				t.Errorf("surface = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestLineageForSession(t *testing.T) {
	cases := []struct {
		name string
		row  sessionRow
		want models.SessionLineage
		ok   bool
	}{
		{
			name: "hidden session is marked a machine-spawned sidecar",
			row:  sessionRow{ID: "tidy-marmot", Hidden: true},
			want: models.SessionLineage{SessionID: "tidy-marmot", ThreadSource: threadSourceSubagent},
			ok:   true,
		},
		{
			name: "visible session carries no lineage",
			row:  sessionRow{ID: "amber-lantern"},
		},
		{
			name: "empty session id carries no lineage",
			row:  sessionRow{Hidden: true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := lineageForSession(c.row)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, c.ok, got)
			}
			if got != c.want {
				t.Errorf("lineage = %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestSurfaceRulesEmitKnownKinds guards the table against an
// out-of-vocabulary surface kind, which the store would refuse loudly.
func TestSurfaceRulesEmitKnownKinds(t *testing.T) {
	for _, r := range surfaceRules {
		if r.MetaKey == "" {
			t.Error("surfaceRules row with an empty MetaKey")
		}
		if !models.KnownSurface(r.Surface.Surface) {
			t.Errorf("surfaceRules[%s] emits unknown surface kind %q", r.MetaKey, r.Surface.Surface)
		}
		if r.Surface.SurfaceHost == "" {
			t.Errorf("surfaceRules[%s] has no SurfaceHost", r.MetaKey)
		}
	}
}
