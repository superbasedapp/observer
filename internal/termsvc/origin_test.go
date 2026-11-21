package termsvc

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestLaunchFreshRecordsOrigin pins lane cli-2: who started a fresh launch
// reaches its recorded row and the live handle's metadata, and a value
// outside the closed set is never kept in memory.
func TestLaunchFreshRecordsOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   termrun.Origin
		want termrun.Origin
	}{
		{"agent with parent", termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-1"}, termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-1"}},
		{"human cli", termrun.Origin{Initiator: termrun.InitiatorHumanCLI}, termrun.Origin{Initiator: termrun.InitiatorHumanCLI}},
		{"not recorded", termrun.Origin{}, termrun.Origin{}},
		{"unknown initiator dropped", termrun.Origin{Initiator: "robot"}, termrun.Origin{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newFakeRecorder()
			l := &fakeLauncher{handle: "HANDLE"}
			svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, l, termfeed.New(termfeed.Options{}))
			if _, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude", Origin: tc.in}); err != nil {
				t.Fatalf("LaunchFresh: %v", err)
			}
			if len(rec.runs) != 1 || rec.runs[0].Origin != tc.in {
				t.Fatalf("recorded runs = %+v, want one with origin %+v", rec.runs, tc.in)
			}
			got, ok := svc.Origin("HANDLE")
			if !ok || got != tc.want {
				t.Fatalf("Origin(HANDLE) = %+v, %v; want %+v", got, ok, tc.want)
			}
		})
	}
}
