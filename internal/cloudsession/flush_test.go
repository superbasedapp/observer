package cloudsession

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func envOf(m map[string]string) LookupEnv {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestDetect(t *testing.T) {
	cc, _ := AgentByID("claude-code")
	cp, _ := AgentByID("copilot")
	cases := []struct {
		name    string
		agent   Agent
		env     map[string]string
		inCloud bool
		loc     ExecutionLocation
		ref     string
	}{
		{"claude local", cc, map[string]string{}, false, "", ""},
		{"claude remote false", cc, map[string]string{"CLAUDE_CODE_REMOTE": "false"}, false, "", ""},
		{"claude cloud", cc, map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "cse_123"}, true, ExecutionVendorCloud, "cse_123"},
		{"claude bad ref", cc, map[string]string{"CLAUDE_CODE_REMOTE": "true", "CLAUDE_CODE_REMOTE_SESSION_ID": "a b"}, true, ExecutionVendorCloud, ""},
		{"claude ref without marker", cc, map[string]string{"CLAUDE_CODE_REMOTE_SESSION_ID": "cse_1"}, false, "", ""},
		{"copilot hosted", cp, map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, true, ExecutionVendorCloud, ""},
		{"copilot self-hosted", cp, map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}, true, ExecutionCustomerWorker, ""},
		{"copilot local", cp, map[string]string{"RUNNER_ENVIRONMENT": "self-hosted"}, false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Detect(tc.agent, envOf(tc.env))
			if d.InCloud != tc.inCloud || d.Location != tc.loc || d.VendorRef != tc.ref {
				t.Fatalf("Detect = %+v, want inCloud=%v loc=%q ref=%q", d, tc.inCloud, tc.loc, tc.ref)
			}
		})
	}
	if _, ok := DetectAny(envOf(map[string]string{})); ok {
		t.Error("DetectAny matched on an empty environment")
	}
	if d, ok := DetectAny(envOf(map[string]string{"CLAUDE_CODE_REMOTE": "true"})); !ok || d.Agent != "claude-code" {
		t.Errorf("DetectAny = %+v, %v", d, ok)
	}
	if d := Detect(cc, nil); d.InCloud {
		t.Error("nil env matched")
	}
}

func TestShouldFlush(t *testing.T) {
	cases := []struct {
		trig       Trigger
		prev, each int
		run        bool
		count      int
	}{
		{TriggerFinal, 7, 0, true, 7},
		{TriggerStart, 7, 3, true, 7},
		{TriggerPrompt, 2, 3, true, 2},
		{TriggerPeriodic, 0, 3, false, 1},
		{TriggerPeriodic, 2, 3, true, 3},
		{TriggerPeriodic, 3, 3, false, 4},
		{TriggerPeriodic, 24, 0, true, 25},
		{TriggerPeriodic, -5, 1, true, 1},
	}
	for _, tc := range cases {
		d, err := ShouldFlush(tc.trig, tc.prev, tc.each)
		if err != nil {
			t.Fatal(err)
		}
		if d.Run != tc.run || d.Count != tc.count {
			t.Errorf("ShouldFlush(%s,%d,%d) = %+v, want run=%v count=%d", tc.trig, tc.prev, tc.each, d, tc.run, tc.count)
		}
	}
	if _, err := ShouldFlush("weekly", 0, 0); err == nil {
		t.Error("unknown trigger accepted")
	}
}

func TestResolveDestination(t *testing.T) {
	cases := []struct {
		kind     DestinationKind
		target   string
		endpoint string
		err      string
	}{
		{DestOrg, "https://org.example.com", "https://org.example.com/ingest/cloud-session/v1/batch", ""},
		{DestOrg, "https://org.example.com/base/", "https://org.example.com/base/ingest/cloud-session/v1/batch", ""},
		{DestNode, "http://127.0.0.1:8822", "http://127.0.0.1:8822/api/cloud-session/ingest", ""},
		{DestNode, "http://node.tailnet:8822", "", "https"},
		{DestNode, "http://127.0.0.2:8822", "http://127.0.0.2:8822/api/cloud-session/ingest", ""},
		{DestNode, "http://localhost:8822", "http://localhost:8822/api/cloud-session/ingest", ""},
		{DestNode, "http://LOCALHOST:8822", "http://LOCALHOST:8822/api/cloud-session/ingest", ""},
		{DestNode, "http://[::1]:8822", "http://[::1]:8822/api/cloud-session/ingest", ""},
		{DestNode, "http://127.attacker.example:8822", "", "https"},
		{DestNode, "http://127.0.0.1.nip.io:8822", "", "https"},
		{DestNode, "http://localhost.attacker.example:8822", "", "https"},
		{DestNode, "http://[fe80::1%25eth0]:8822", "", "https"},
		{DestOrg, "https://u:p@org.example.com", "", "credentials"},
		{DestOrg, "https://org.example.com?x=1", "", "query"},
		{DestOrg, "", "", "needs a target"},
		{DestOrg, "ftp://org", "", "https"},
		{"carrier-pigeon", "x", "", "unknown destination"},
	}
	for _, tc := range cases {
		d, err := ResolveDestination(tc.kind, tc.target)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s %q: err = %v, want %q", tc.kind, tc.target, err, tc.err)
			}
			continue
		}
		if err != nil || d.Endpoint != tc.endpoint || !d.NeedsToken || !d.Network {
			t.Errorf("%s %q = %+v, %v; want endpoint %s", tc.kind, tc.target, d, err, tc.endpoint)
		}
	}
	d, err := ResolveDestination(DestFile, "/tmp/out")
	if err != nil || d.Dir != "/tmp/out" || d.Network || d.NeedsToken {
		t.Errorf("file destination = %+v, %v", d, err)
	}
}

type fakeStamper struct {
	got  []Stamp
	fail bool
}

func (f *fakeStamper) SetSessionExecution(_ context.Context, id, loc, ref string) (bool, error) {
	if f.fail {
		return false, errors.New("boom")
	}
	f.got = append(f.got, Stamp{SessionID: id, Location: ExecutionLocation(loc), VendorRef: ref})
	return true, nil
}

func TestStamps(t *testing.T) {
	det := Detection{Agent: "claude-code", InCloud: true, Location: ExecutionVendorCloud, VendorRef: "cse_1"}
	stamps := PlanStamps(det, []string{"a", "b", "a", ""})
	if len(stamps) != 2 {
		t.Fatalf("stamps = %+v", stamps)
	}
	if got := PlanStamps(Detection{}, []string{"a"}); got != nil {
		t.Errorf("stamped outside the cloud: %+v", got)
	}
	n, err := ApplyStamps(context.Background(), nil, stamps)
	if n != 0 || err != nil {
		t.Errorf("nil stamper = %d, %v", n, err)
	}
	f := &fakeStamper{}
	if n, err := ApplyStamps(context.Background(), f, stamps); n != 2 || err != nil || f.got[1].VendorRef != "cse_1" {
		t.Errorf("ApplyStamps = %d, %v, %+v", n, err, f.got)
	}
	if _, err := ApplyStamps(context.Background(), &fakeStamper{fail: true}, stamps); err == nil {
		t.Error("stamper error swallowed")
	}
}

// TestAgentTableIsConsistent: every supported row names a registry tool
// with a hook receiver and a known file format; ids are unique.
func TestAgentTableIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Agents() {
		if seen[a.ID] {
			t.Errorf("duplicate agent %q", a.ID)
		}
		seen[a.ID] = true
		if !a.Supported() {
			if len(a.Files) != 0 || len(a.Hooks) != 0 {
				t.Errorf("%s is unsupported but declares files or hooks", a.ID)
			}
			continue
		}
		if _, ok := integration.For(a.HookTool); !ok {
			t.Errorf("%s: hook tool %q is not an integration registry tool", a.ID, a.HookTool)
		}
		for _, ad := range a.ScanAdapters {
			if _, ok := integration.For(ad); !ok {
				t.Errorf("%s: scan adapter %q is not an integration registry tool", a.ID, ad)
			}
		}
		if len(a.Markers) == 0 {
			t.Errorf("%s has no cloud marker: its hooks would run on a developer machine", a.ID)
		}
		// The cadence never rests on Stop/SessionEnd alone (CA-A2 saw
		// neither fire): every agent flushes at start, per prompt and
		// periodically, and keeps the final flush as a bonus.
		flushes := map[Trigger]bool{}
		for _, b := range a.Hooks {
			if b.Action == ActionFlush {
				if _, err := TriggerSpecFor(b.Trigger); err != nil {
					t.Errorf("%s %s: %v", a.ID, b.Event, err)
				}
				flushes[b.Trigger] = true
			} else if b.Trigger != "" {
				t.Errorf("%s %s: a capture entry carries a flush trigger", a.ID, b.Event)
			}
		}
		for _, trig := range Triggers() {
			if !flushes[trig] {
				t.Errorf("%s has no %s flush hook", a.ID, trig)
			}
		}
		if _, ok := HookFile(a); !ok {
			t.Errorf("%s has no hook file for the self-modification guard", a.ID)
		}
		for _, f := range a.Files {
			if _, err := rendererFor(f.Format); err != nil {
				t.Errorf("%s: %v", a.ID, err)
			}
		}
	}
}

func TestExecutionLocationVocabulary(t *testing.T) {
	// The spelling lane CA-A1 adds to internal/models (plan section 4.1).
	want := map[ExecutionLocation]string{ExecutionLocal: "local", ExecutionVendorCloud: "vendor_cloud", ExecutionCustomerWorker: "customer_worker"}
	for k, v := range want {
		if string(k) != v {
			t.Errorf("%q != %q", k, v)
		}
	}
}

func TestPackageImportsArePure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net", "net/http", "os", "os/exec",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/internal/"},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/textdiff",
			"github.com/marmutapp/superbased-observer/internal/integration",
			// The wire contract owns the policy-bundle and budget signing
			// messages (lane CA-C2): verifying through it keeps one recipe.
			"github.com/marmutapp/superbased-observer/internal/orgcontract",
			"github.com/marmutapp/superbased-observer/internal/testsupport/importpin",
		},
		Reason: "cloudsession is pure; its only egress is internal/cloudsessionnet",
	})
}

func TestJSONRoundTrip(t *testing.T) {
	escaped := "{\n  \"a\": \"x" + `\` + "u00e9\"\n}"
	for _, s := range []string{"{}\n", "[]", "{\n  \"a\": [\n    1,\n    2.50,\n    \"x\"\n  ],\n  \"b\": null\n}"} {
		d, err := loadJSONDoc(s)
		if err != nil {
			t.Fatal(err)
		}
		if !d.roundTrips {
			t.Errorf("%q does not round-trip: %q", s, d.render())
		}
	}
	d, err := loadJSONDoc(escaped)
	if err != nil {
		t.Fatal(err)
	}
	if d.roundTrips {
		t.Errorf("an escaped string re-encodes differently, so %q must not round-trip", escaped)
	}
	if _, err := parseJSON(`{"a":1,"a":2}`); err == nil {
		t.Error("duplicate key accepted")
	}
	if _, err := parseJSON(`{} x`); err == nil {
		t.Error("trailing content accepted")
	}
}

// TestMarkerEnvNames: every variable Detect reads for an agent, each once,
// in table order; an agent with no markers names none.
func TestMarkerEnvNames(t *testing.T) {
	for _, tc := range []struct {
		agent string
		want  []string
	}{
		{"claude-code", []string{"CLAUDE_CODE_REMOTE", "CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE", WorkerAttestEnv, "CLAUDE_CODE_REMOTE_SESSION_ID"}},
		{"copilot", []string{"GITHUB_ACTIONS", "RUNNER_ENVIRONMENT"}},
		{"openhands", nil},
	} {
		a, err := AgentByID(tc.agent)
		if err != nil {
			t.Fatal(err)
		}
		if got := MarkerEnvNames(a); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: %v, want %v", tc.agent, got, tc.want)
		}
	}
}
