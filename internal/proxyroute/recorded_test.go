package proxyroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// TestRecordedRoutesCline is FU-77: a Cline route Observer wrote and
// recorded is read back at its recorded member, and a later rewrite of
// globalState.json that dropped or changed it is reported, never the value.
func TestRecordedRoutesCline(t *testing.T) {
	routed := clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"planModeApiProvider\": \"openai\"")
	cases := []struct {
		name string
		// after rewrites (or removes, when absent) globalState.json once the
		// route was written; "" leaves the file as the writer left it.
		after  string
		absent bool
		want   RecordedRouteState
	}{
		{name: "recorded and present", want: RecordedRoutePresent},
		{name: "a running Cline wrote its state back without the member", after: routed, want: RecordedRouteMissing},
		{name: "the member was emptied", after: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"\""), want: RecordedRouteMissing},
		{name: "changed to a foreign host", after: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"https://gateway.corp.example/v1\""), want: RecordedRouteChanged},
		{name: "changed to another observer port", after: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"http://127.0.0.1:9900/v1\""), want: RecordedRouteChanged},
		{name: "the state file is gone", absent: true, want: RecordedRouteConfigGone},
		{name: "the state file is not JSON any more", after: "{\"someLegacyKey\": \"" + clineFakeKey + "\", ", want: RecordedRouteUnreadable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clineHermetic(t)
			home := t.TempDir()
			path := clineStatePath(home)
			seedClineState(t, path, routed)
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterInit})
			if err != nil {
				t.Fatal(err)
			}
			if res := r.RegisterCline(); !res.Added || res.Error != nil || res.ProvenanceError != nil {
				t.Fatalf("route write = %+v", res)
			}
			switch {
			case tc.absent:
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case tc.after != "":
				seedClineState(t, path, tc.after)
			}
			got, err := RecordedRoutes(home)
			if err != nil {
				t.Fatalf("RecordedRoutes: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d recorded routes, want 1: %+v", len(got), got)
			}
			rr := got[0]
			if rr.Tool != "cline" || filepath.ToSlash(rr.ConfigPath) != filepath.ToSlash(path) {
				t.Errorf("target = %s %s, want cline %s", rr.Tool, rr.ConfigPath, path)
			}
			if rr.State != tc.want {
				t.Errorf("state = %s, want %s", rr.State, tc.want)
			}
			if rr.Setting != "openAiBaseUrl" || rr.Writer != routeprov.WriterInit {
				t.Errorf("setting/writer = %q/%q", rr.Setting, rr.Writer)
			}
			if (rr.State == RecordedRouteUnreadable) != (rr.Err != nil) {
				t.Errorf("err = %v for state %s", rr.Err, rr.State)
			}
			if rr.Err != nil && strings.Contains(rr.Err.Error(), clineFakeKey) {
				t.Errorf("the error quotes the file: %v", rr.Err)
			}
		})
	}
}

// TestRecordedRoutesFileStates: no provenance file reads as no records, an
// unreadable one is an error, a record for a tool with no route reader is
// left out, and the reading dispatches on the route shape for every tool
// (a Claude Code record, not only Cline's).
func TestRecordedRoutesFileStates(t *testing.T) {
	t.Run("no provenance file", func(t *testing.T) {
		got, err := RecordedRoutes(t.TempDir())
		if err != nil || len(got) != 0 {
			t.Fatalf("got %+v, %v; want none", got, err)
		}
	})
	t.Run("unreadable provenance file", func(t *testing.T) {
		home := t.TempDir()
		p := filepath.Join(home, ".observer", ProvenanceFileName)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := RecordedRoutes(home); err == nil || got != nil {
			t.Fatalf("got %+v, %v; want an error", got, err)
		}
	})
	t.Run("a claude-code record and a reader-less record", func(t *testing.T) {
		home := t.TempDir()
		settings := filepath.Join(home, ".claude", "settings.json")
		if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settings, []byte(`{"env":{"OTHER":"1"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		f := routeprov.File{Records: []routeprov.Record{
			{Tool: "claude-code", ConfigPath: settings, Value: "http://127.0.0.1:8820", Writer: routeprov.WriterEnrolment},
			{Tool: "no-such-tool", ConfigPath: filepath.Join(home, "x.json"), Value: "http://127.0.0.1:8820", Writer: routeprov.WriterInit},
		}}
		if err := saveProvenance(filepath.Join(home, ".observer", ProvenanceFileName), f); err != nil {
			t.Fatal(err)
		}
		got, err := RecordedRoutes(home)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Tool != "claude-code" || got[0].State != RecordedRouteMissing || got[0].Setting != "ANTHROPIC_BASE_URL" {
			t.Fatalf("got %+v, want one missing claude-code route", got)
		}
	})
}

// TestClassifyRecordedRules pins the classification table row by row.
func TestClassifyRecordedRules(t *testing.T) {
	cases := []struct {
		name string
		in   recordedReading
		want RecordedRouteState
	}{
		{"config gone wins over everything", recordedReading{configGone: true, err: os.ErrPermission}, RecordedRouteConfigGone},
		{"read error", recordedReading{err: os.ErrPermission, present: true, current: "a", recorded: "a"}, RecordedRouteUnreadable},
		{"not present", recordedReading{recorded: "a"}, RecordedRouteMissing},
		{"another value", recordedReading{present: true, current: "b", recorded: "a"}, RecordedRouteChanged},
		{"the recorded value", recordedReading{present: true, current: "a", recorded: "a"}, RecordedRoutePresent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRecorded(tc.in); got != tc.want {
				t.Errorf("classifyRecorded = %s, want %s", got, tc.want)
			}
		})
	}
}
