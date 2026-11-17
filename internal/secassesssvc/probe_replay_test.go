package secassesssvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// Tests of the request helper's replay mode (depth plan W7.2): the stored
// requests of a retest ride in probe.json and `probe.py --replay ID` sends them
// in order, each logged as a replay of that finding. They run the real helper
// with a real Python 3 and skip when none is installed (see probe_helper_test.go).

// replayConfig is a probe.json "replay" value: F-1 holds two stored requests,
// the first with a hidden credential header.
func replayConfig() map[string]any {
	return map[string]any{
		"F-1": map[string]any{"wstg": "ATHN", "steps": []any{
			map[string]any{"method": "POST", "path": "/echo", "body": "a=1&b=2", "headers": []any{
				map[string]any{"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
				map[string]any{"name": "Authorization", "value": "Bearer [REDACTED]"},
				map[string]any{"name": "Cookie", "value": ""},
				map[string]any{"name": "X-Test", "value": "1"},
			}},
			map[string]any{"method": "GET", "path": "/ok"},
		}},
		"F-2": map[string]any{"steps": []any{map[string]any{"method": "GET", "path": "/status/404"}}},
	}
}

func withReplay(r map[string]any) probeHelperOpts {
	return probeHelperOpts{cfg: func(c map[string]any) { c["replay"] = r }}
}

func TestProbeHelperReplay(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, withReplay(replayConfig()))
	out := run.probe("--replay", "F-1")
	if out.Exit != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", out.Exit, out.Stdout, out.Stderr)
	}
	if run.srv.count() != 2 {
		t.Fatalf("the target saw %d requests, want the 2 stored ones", run.srv.count())
	}
	first, second := run.srv.at(0), run.srv.at(1)
	if first.Method != "POST" || first.URI != "/echo" || first.Body != "a=1&b=2" {
		t.Errorf("first request = %+v", first)
	}
	if first.Header.Get("X-Test") != "1" || first.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("a stored header was not sent: %v", first.Header)
	}
	if first.Header.Get("Authorization") != "" || first.Header.Get("Cookie") != "" {
		t.Errorf("a header whose stored value was hidden or empty was sent: %v", first.Header)
	}
	if second.Method != "GET" || second.URI != "/ok" {
		t.Errorf("second request = %+v", second)
	}
	recs := run.log()
	if len(recs) != 2 {
		t.Fatalf("%d log lines", len(recs))
	}
	for i, r := range recs {
		if r.Replay != "F-1" || r.WSTG != "ATHN" || !r.Sent || r.Status != 200 || r.ID != fmt.Sprintf("p%d", i+1) {
			t.Errorf("record %d = %+v", i+1, r)
		}
	}
	if recs[0].Role != "" || recs[1].Role != "attack" {
		t.Errorf("roles %q %q: only the last stored request is the attack", recs[0].Role, recs[1].Role)
	}
	if !strings.Contains(recs[0].Note, "replay F-1 step 1 of 2") || !strings.Contains(recs[0].Note, "Authorization") || !strings.Contains(recs[0].Note, "Cookie") {
		t.Errorf("note = %q", recs[0].Note)
	}
	if strings.Contains(recs[0].Note, "X-Test") {
		t.Errorf("the note names a header that was sent: %q", recs[0].Note)
	}
	if !strings.Contains(out.Stdout, "probe p1 POST /echo -> 200") || !strings.Contains(out.Stdout, "probe p2 GET /ok -> 200") {
		t.Errorf("stdout = %q", out.Stdout)
	}
	if !strings.Contains(out.Stderr, "Authorization was hidden") {
		t.Errorf("stderr = %q", out.Stderr)
	}
	// The log it wrote is one the pure core reads like any helper log, with the replay tag kept.
	raw := run.rawLog()
	parsed := secassess.ParseProbeLog([]byte(raw))
	if parsed.Problem != "" || len(parsed.Records) != 2 || parsed.Records[1].Replay != "F-1" {
		t.Errorf("the pure core reads the log as %+v", parsed)
	}
	// The next replay continues the ids and the other finding is tagged on its own.
	out = run.probe("--replay", "F-2")
	if out.Exit != 0 || run.last().ID != "p3" || run.last().Replay != "F-2" || run.last().WSTG != "" || run.last().Status != 404 {
		t.Errorf("second replay: exit %d, last %+v", out.Exit, run.last())
	}
}

func TestProbeHelperReplayRefusals(t *testing.T) {
	t.Parallel()
	t.Run("a finding with nothing stored", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, withReplay(replayConfig()))
		out := run.probe("--replay", "F-9")
		if out.Exit != 3 || !strings.Contains(out.Stderr, "(no_replay)") {
			t.Errorf("exit %d stderr %q", out.Exit, out.Stderr)
		}
		if run.srv.count() != 0 || len(run.log()) != 0 {
			t.Errorf("a replay with nothing to send sent %d requests and logged %d lines", run.srv.count(), len(run.log()))
		}
	})
	t.Run("a run with no stored requests", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, probeHelperOpts{})
		if out := run.probe("--replay", "F-1"); out.Exit != 3 || !strings.Contains(out.Stderr, "(no_replay)") || run.srv.count() != 0 {
			t.Errorf("exit %d stderr %q", out.Exit, out.Stderr)
		}
	})
	t.Run("an id that is not a finding id", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, withReplay(replayConfig()))
		for _, id := range []string{"../F-1", "F 1", strings.Repeat("a", 60)} {
			if out := run.probe("--replay", id); out.Exit != 3 || !strings.Contains(out.Stderr, "(no_replay)") {
				t.Errorf("%q: exit %d stderr %q", id, out.Exit, out.Stderr)
			}
		}
		if run.srv.count() != 0 {
			t.Error("a request was sent")
		}
	})
	t.Run("replay takes no method, target, header or data", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, withReplay(replayConfig()))
		for _, args := range [][]string{{"--replay", "F-1", "GET", "/ok"}, {"--replay", "F-1", "-H", "X: y"}, {"--replay", "F-1", "-d", "a"}} {
			if out := run.probe(args...); out.Exit != 2 {
				t.Errorf("%v: exit %d, want a usage error", args, out.Exit)
			}
		}
		if run.srv.count() != 0 {
			t.Error("a request was sent")
		}
	})
	t.Run("a request still needs a method and a target without replay", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, probeHelperOpts{})
		for _, args := range [][]string{{}, {"GET"}} {
			if out := run.probe(args...); out.Exit != 2 {
				t.Errorf("%v: exit %d, want a usage error", args, out.Exit)
			}
		}
	})
	t.Run("a refused step is logged as a replay and ends it", func(t *testing.T) {
		t.Parallel()
		r := map[string]any{"F-1": map[string]any{"steps": []any{
			map[string]any{"method": "GET", "path": "//evil.example/x"},
			map[string]any{"method": "GET", "path": "/ok"},
		}}}
		run := newProbeHelperRun(t, withReplay(r))
		out := run.probe("--replay", "F-1")
		if out.Exit != 3 || !strings.Contains(out.Stderr, "(bad_path)") {
			t.Errorf("exit %d stderr %q", out.Exit, out.Stderr)
		}
		recs := run.log()
		if len(recs) != 1 || recs[0].Refused != "bad_path" || recs[0].Replay != "F-1" || recs[0].Sent {
			t.Errorf("log = %+v", recs)
		}
		if run.srv.count() != 0 {
			t.Errorf("the target saw %d requests", run.srv.count())
		}
	})
	t.Run("the budget holds for a replay", func(t *testing.T) {
		t.Parallel()
		o := withReplay(replayConfig())
		base := o.cfg
		o.cfg = func(c map[string]any) { base(c); c["budget"] = 1 }
		run := newProbeHelperRun(t, o)
		out := run.probe("--replay", "F-1")
		recs := run.log()
		if out.Exit != 3 || len(recs) != 2 || !recs[0].Sent || recs[1].Refused != "budget" || recs[1].Replay != "F-1" || run.srv.count() != 1 {
			t.Errorf("exit %d, log %+v, target saw %d", out.Exit, recs, run.srv.count())
		}
	})
	t.Run("a response of none gives exit 1 and the replay goes on", func(t *testing.T) {
		t.Parallel()
		o := withReplay(replayConfig())
		o.origin = probeHelperClosedOrigin(t)
		run := newProbeHelperRun(t, o)
		out := run.probe("--replay", "F-1")
		recs := run.log()
		if out.Exit != 1 || len(recs) != 2 || recs[0].Error == "" || recs[1].Error == "" {
			t.Errorf("exit %d, log %+v", out.Exit, recs)
		}
	})
}

// TestProbeHelperReplayBadConfig: a replay value the helper cannot read whole
// refuses every request, so a half-read set is never used.
func TestProbeHelperReplayBadConfig(t *testing.T) {
	t.Parallel()
	step := func(m map[string]any) map[string]any { return map[string]any{"steps": []any{m}} }
	many := map[string]any{}
	for i := 0; i < 9; i++ {
		many[fmt.Sprintf("F-%d", i)] = step(map[string]any{"method": "GET", "path": "/ok"})
	}
	var steps []any
	for i := 0; i < 9; i++ {
		steps = append(steps, map[string]any{"method": "GET", "path": "/ok"})
	}
	rows := []struct {
		name string
		v    any
	}{
		{"not an object", []any{}},
		{"nine findings", many},
		{"nine steps", map[string]any{"F-1": map[string]any{"steps": steps}}},
		{"no steps", map[string]any{"F-1": map[string]any{"steps": []any{}}}},
		{"an id with a space", map[string]any{"F 1": step(map[string]any{"method": "GET", "path": "/ok"})}},
		{"a step with no path", map[string]any{"F-1": step(map[string]any{"method": "GET"})}},
		{"a method that is not text", map[string]any{"F-1": step(map[string]any{"method": 5, "path": "/ok"})}},
		{"a header with no name", map[string]any{"F-1": step(map[string]any{"method": "GET", "path": "/ok", "headers": []any{map[string]any{"value": "x"}}})}},
		{"a body that is not text", map[string]any{"F-1": step(map[string]any{"method": "GET", "path": "/ok", "body": 5})}},
		{"a category that is not a WSTG one", map[string]any{"F-1": map[string]any{"wstg": "EVIL", "steps": []any{map[string]any{"method": "GET", "path": "/ok"}}}}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			run := newProbeHelperRun(t, withReplay(map[string]any{}))
			cfg, err := os.ReadFile(filepath.Join(run.dir, "probe.json"))
			if err != nil {
				t.Fatal(err)
			}
			var c map[string]any
			if err := json.Unmarshal(cfg, &c); err != nil {
				t.Fatal(err)
			}
			c["replay"] = row.v
			data, _ := json.Marshal(c)
			if err := os.WriteFile(filepath.Join(run.dir, "probe.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			// Both a replay and a plain request are refused: the file is bad as a whole.
			for _, args := range [][]string{{"--replay", "F-1"}, {"GET", "/ok"}} {
				out := run.probe(args...)
				if out.Exit != 3 || !strings.Contains(out.Stderr, "(bad_config)") {
					t.Errorf("%v: exit %d stderr %q", args, out.Exit, out.Stderr)
				}
			}
			if run.srv.count() != 0 {
				t.Error("a request was sent")
			}
		})
	}
}

// TestProbeHelperReadsALargeConfig: a settings file the size of a full retest
// (up to MaxProbeConfigBytes) is read whole; one past the helper's cap is refused.
func TestProbeHelperReadsALargeConfig(t *testing.T) {
	t.Parallel()
	big := map[string]any{"F-1": map[string]any{"steps": []any{map[string]any{"method": "POST", "path": "/echo", "body": strings.Repeat("x", 2000)}}}}
	for i := 2; i <= 8; i++ {
		var steps []any
		for j := 0; j < 8; j++ {
			steps = append(steps, map[string]any{"method": "GET", "path": "/ok", "body": strings.Repeat("y", 2000)})
		}
		big[fmt.Sprintf("F-%d", i)] = map[string]any{"steps": steps}
	}
	run := newProbeHelperRun(t, withReplay(big))
	if fi, err := os.Stat(filepath.Join(run.dir, "probe.json")); err != nil || fi.Size() < 100<<10 || fi.Size() > MaxProbeConfigBytes {
		t.Fatalf("the fixture is %v bytes (%v)", fi.Size(), err)
	}
	if out := run.probe("--replay", "F-1"); out.Exit != 0 || run.srv.count() != 1 {
		t.Errorf("exit %d stderr %q, target saw %d", out.Exit, out.Stderr, run.srv.count())
	}
	// Past 256 KiB the helper refuses (Observer never writes such a file).
	over := newProbeHelperRun(t, withReplay(map[string]any{"F-1": map[string]any{"steps": []any{map[string]any{"method": "POST", "path": "/echo", "body": strings.Repeat("z", 300<<10)}}}}))
	if out := over.probe("GET", "/ok"); out.Exit != 3 || !strings.Contains(out.Stderr, "(bad_config)") || over.srv.count() != 0 {
		t.Errorf("exit %d stderr %q", out.Exit, out.Stderr)
	}
}

// TestProbeHelperPythonReplayAPI: replay() is the one way to tag a record, and a
// request sent by request() carries no replay key.
func TestProbeHelperPythonReplayAPI(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, withReplay(replayConfig()))
	script := filepath.Join(run.dir, "use.py")
	src := `import sys
sys.path.insert(0, ".")
import probe
probe.request("GET", "/ok")
got = probe.replay("F-1", each=lambda r: print("each", r["id"], r["unsent_headers"]))
print("n", len(got))
try:
    probe.replay("nope")
except probe.ProbeRefused as exc:
    print("refused", exc.code)
`
	if err := os.WriteFile(script, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run.py3(script, run.dir)
	if err != nil || out.Exit != 0 {
		t.Fatalf("script: %v exit %d stderr %q", err, out.Exit, out.Stderr)
	}
	for _, w := range []string{"each p2 ['Authorization', 'Cookie']", "each p3 []", "n 2", "refused no_replay"} {
		if !strings.Contains(out.Stdout, w) {
			t.Errorf("stdout lacks %q: %q", w, out.Stdout)
		}
	}
	recs := run.log()
	if len(recs) != 3 || recs[0].Replay != "" || recs[1].Replay != "F-1" || recs[2].Replay != "F-1" {
		t.Errorf("log = %+v", recs)
	}
}

// TestProbeConfigBytesReplay: a retest's stored requests are in the settings
// file, a plain run's file is the same bytes as before, and a set too large for
// the file is refused.
func TestProbeConfigBytesReplay(t *testing.T) {
	target, err := secassess.ParseTarget("http://localhost:3000/")
	if err != nil {
		t.Fatal(err)
	}
	in := ProbeInput{RunID: svcRun, Target: target, Budget: 600, PaceRPS: 5}
	plain, err := in.ConfigBytes()
	if err != nil || strings.Contains(string(plain), "replay") {
		t.Fatalf("a plain run's settings %q carry a replay key (%v)", plain, err)
	}
	in.Replay = (&secassess.RetestBasis{Of: "x", Findings: []secassess.RetestFinding{{
		ID: "F-1", Category: "ATHN", Steps: []secassess.PTRepro{{Request: &secassess.PTRequest{Method: "GET", Path: "/a?b=<c>&d=e"}}},
	}}}).ReplaySet()
	with, err := in.ConfigBytes()
	if err != nil {
		t.Fatal(err)
	}
	var c ProbeConfig
	if err := json.Unmarshal(with, &c); err != nil || c.Replay["F-1"].WSTG != "ATHN" || c.Replay["F-1"].Steps[0].Path != "/a?b=<c>&d=e" {
		t.Fatalf("config = %+v (%v)", c, err)
	}
	if again, _ := in.ConfigBytes(); string(again) != string(with) {
		t.Error("the bytes are not deterministic")
	}
	huge := map[string]secassess.ReplayEntry{}
	for i := 0; i < 8; i++ {
		e := secassess.ReplayEntry{}
		for j := 0; j < 8; j++ {
			e.Steps = append(e.Steps, secassess.ReplayStep{Method: "POST", Path: "/p", Body: strings.Repeat("b", 2048), Headers: manyHeaders()})
		}
		huge[fmt.Sprintf("F-%d", i)] = e
	}
	in.Replay = huge
	if _, err := in.ConfigBytes(); !errors.Is(err, ErrProbeConfigTooLarge) {
		t.Errorf("the largest set a retest can hold: err = %v, want ErrProbeConfigTooLarge", err)
	}
}

// TestReplayedFindings: the finding ids the agent's self-check reads are the
// ones Observer wrote into probe.json, sorted; a run with no replay set, no
// settings, settings that are not JSON, or an id that is not an item id lists
// only what is a finding.
func TestReplayedFindings(t *testing.T) {
	target, err := secassess.ParseTarget("http://localhost:3000/")
	if err != nil {
		t.Fatal(err)
	}
	basis := &secassess.RetestBasis{Of: "x"}
	for _, id := range []string{"F-3", "F-1", "F-2"} {
		basis.Findings = append(basis.Findings, secassess.RetestFinding{ID: id, Steps: []secassess.PTRepro{{Request: &secassess.PTRequest{Method: "GET", Path: "/a"}}}})
	}
	root := t.TempDir()
	cleanup, err := PrepareRunDir(root, svcRun)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got := ReplayedFindings(root, svcRun); len(got) != 0 {
		t.Errorf("a run folder with no settings lists %v", got)
	}
	if _, _, err := WriteProbeFiles(root, ProbeInput{RunID: svcRun, Target: target, Budget: 600, PaceRPS: 5, Replay: basis.ReplaySet()}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ReplayedFindings(root, svcRun), ","); got != "F-1,F-2,F-3" {
		t.Errorf("the replayed findings = %q, want F-1,F-2,F-3", got)
	}
	p := filepath.Join(root, filepath.FromSlash(secassess.ResultPaths(svcRun).ProbeConfig))
	for name, body := range map[string]string{
		"a settings file with no replay set": `{"schema":"x"}`,
		"a settings file that is not JSON":   `{nope`,
		"a replay set of one bad id":         `{"replay":{"bad id":{}}}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ReplayedFindings(root, svcRun); len(got) != 0 {
			t.Errorf("%s lists %v", name, got)
		}
	}
	if got := ReplayedFindings(root, "not a run"); len(got) != 0 {
		t.Errorf("a bad run id lists %v", got)
	}
}

// manyHeaders is eight headers of the longest stored value.
func manyHeaders() []secassess.PTHeader {
	var hs []secassess.PTHeader
	for i := 0; i < 8; i++ {
		hs = append(hs, secassess.PTHeader{Name: fmt.Sprintf("X-Header-%d", i), Value: strings.Repeat("v", 256)})
	}
	return hs
}
