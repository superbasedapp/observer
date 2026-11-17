package secassesssvc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The service half of the request helper (depth plan W5b): the embedded script
// and what the service does with it. The helper's own behaviour is held by
// probe_helper_test.go, which runs it with a real Python.

// TestProbeEmbedHoldsOnlyTheHelper: the embedded directory holds probe.py and
// nothing else (the import pins forbid an Observer package from the service,
// so the helper is data, and a second file in the directory would ship by
// accident), and the embedded bytes are the file's.
func TestProbeEmbedHoldsOnlyTheHelper(t *testing.T) {
	entries, err := os.ReadDir("probe")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "probe.py" {
		t.Fatalf("the embed directory holds %v, want only probe.py", names)
	}
	disk, err := os.ReadFile(filepath.Join("probe", "probe.py"))
	if err != nil {
		t.Fatal(err)
	}
	if string(disk) != string(probeSource) {
		t.Error("the embedded helper is not the file on disk")
	}
	if got, want := ProbeHelperSHA256(), sha256Hex(disk); got != want || len(got) != 64 {
		t.Errorf("ProbeHelperSHA256 = %q, want %q", got, want)
	}
	if ProbeHelperSize() != len(disk) || len(disk) > 40<<10 {
		t.Errorf("helper size %d (disk %d): the plan says about 200 lines", ProbeHelperSize(), len(disk))
	}
	if strings.Contains(string(disk), "\r") {
		t.Error("the helper has CR bytes; the run folder holds the bytes the hash names")
	}
}

func TestPlanProbe(t *testing.T) {
	seen := secassess.ToolFacts{"python3": true, "curl": true}
	absent := secassess.ToolFacts{"python3": false, "curl": true}
	cases := []struct {
		name    string
		setting bool
		tools   secassess.ToolFacts
		mode    string
		reason  bool
	}{
		{"on and python3 seen", true, seen, secassess.HelperOn, false},
		{"off writes nothing", false, seen, secassess.HelperOff, false},
		{"off without python3 is off, not withheld", false, absent, secassess.HelperOff, false},
		{"on without python3 is withheld", true, absent, secassess.HelperWithheld, true},
		{"python3 unknown does not withhold", true, secassess.ToolFacts{"curl": true}, secassess.HelperOn, false},
		{"no inventory at all does not withhold", true, nil, secassess.HelperOn, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := PlanProbe(tc.setting, tc.tools)
			if p.Mode != tc.mode || (p.Reason != "") != tc.reason {
				t.Errorf("PlanProbe = %+v, want mode %q (reason %v)", p, tc.mode, tc.reason)
			}
		})
	}
	if !strings.Contains(WithheldReason, "python3") || !strings.Contains(WithheldReason, "No log") {
		t.Errorf("the withheld sentence names neither python3 nor the evidence word: %q", WithheldReason)
	}
}

func mustTarget(t testing.TB, raw string) secassess.Target {
	t.Helper()
	tg, err := secassess.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestProbeConfigBytes(t *testing.T) {
	good := func(raw string) ProbeInput {
		return ProbeInput{RunID: svcRun, Target: mustTarget(t, raw), Budget: 600, PaceRPS: 5}
	}
	for _, tc := range []struct{ target, origin string }{
		{"http://localhost:3000/", "http://localhost:3000"},
		{"http://127.0.0.1:8080/app?x=1", "http://127.0.0.1:8080"},
		{"https://[::1]:8443/", "https://[::1]:8443"},
		// Spellings ParseTarget accepts and the helper must accept too
		// (TestProbeHelperAcceptsEveryTargetSpelling runs it on each).
		{"http://[::ffff:127.0.0.1]:3000/", "http://[::ffff:127.0.0.1]:3000"},
		{"http://[0:0:0:0:0:0:0:1]:3000/", "http://[0:0:0:0:0:0:0:1]:3000"},
	} {
		b, err := good(tc.target).ConfigBytes()
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if b[len(b)-1] != '\n' || strings.Count(string(b), "\n") != 1 {
			t.Errorf("%s: probe.json is not one line: %q", tc.target, b)
		}
		var c ProbeConfig
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		want := ProbeConfig{Schema: secassess.ProbeConfigSchema, RunID: svcRun, Origin: tc.origin, Budget: 600, PaceRPS: 5, MaxBytes: ProbeMaxBytes}
		if !reflect.DeepEqual(c, want) {
			t.Errorf("%s: config = %+v, want %+v", tc.target, c, want)
		}
		again, _ := good(tc.target).ConfigBytes()
		if string(again) != string(b) {
			t.Errorf("%s: the bytes are not deterministic", tc.target)
		}
	}
	bad := map[string]ProbeInput{
		"a bad run id":  {RunID: "../x", Target: mustTarget(t, "http://localhost:3000/"), Budget: 1, PaceRPS: 1},
		"no target":     {RunID: svcRun, Budget: 1, PaceRPS: 1},
		"a zero budget": {RunID: svcRun, Target: mustTarget(t, "http://localhost:3000/"), Budget: 0, PaceRPS: 1},
		"a zero pace":   {RunID: svcRun, Target: mustTarget(t, "http://localhost:3000/"), Budget: 1, PaceRPS: 0},
	}
	for name, in := range bad {
		if _, err := in.ConfigBytes(); !errors.Is(err, ErrProbeRun) {
			t.Errorf("%s: err = %v, want ErrProbeRun", name, err)
		}
	}
}

// probeProject is a project with the run folder PrepareRunDir makes.
func probeProject(t *testing.T) (root string, in ProbeInput) {
	t.Helper()
	root = t.TempDir()
	if _, err := PrepareRunDir(root, svcRun); err != nil {
		t.Fatal(err)
	}
	return root, ProbeInput{RunID: svcRun, Target: mustTarget(t, "http://localhost:3000/"), Budget: 600, PaceRPS: 5}
}

func TestWriteProbeFiles(t *testing.T) {
	p := secassess.ResultPaths(svcRun)
	read := func(root, rel string) string {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "<" + err.Error() + ">"
		}
		return string(b)
	}
	t.Run("writes both files and reports their hashes", func(t *testing.T) {
		root, in := probeProject(t)
		files, cleanup, err := WriteProbeFiles(root, in)
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := in.ConfigBytes()
		if read(root, p.ProbeHelper) != string(probeSource) || read(root, p.ProbeConfig) != string(cfg) {
			t.Fatal("the files do not hold what was to be written")
		}
		if files.Helper != ProbeHelperSHA256() || files.Config != sha256Hex(cfg) {
			t.Errorf("hashes = %+v", files)
		}
		if runtime.GOOS != "windows" {
			for _, rel := range []string{p.ProbeHelper, p.ProbeConfig} {
				fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
				if err != nil || fi.Mode().Perm() != 0o600 {
					t.Errorf("%s: mode %v, err %v, want 0600", rel, fi.Mode(), err)
				}
			}
		}
		cleanup()
		for _, rel := range []string{p.ProbeHelper, p.ProbeConfig} {
			if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
				t.Errorf("%s is still there after the cleanup", rel)
			}
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p.Dir), ".gitignore")); err != nil {
			t.Errorf("the cleanup removed the run folder's own file: %v", err)
		}
	})
	t.Run("a second write of the same bytes is accepted and creates nothing", func(t *testing.T) {
		root, in := probeProject(t)
		if _, _, err := WriteProbeFiles(root, in); err != nil {
			t.Fatal(err)
		}
		files, cleanup, err := WriteProbeFiles(root, in)
		if err != nil || files.Helper == "" {
			t.Fatalf("second write: %v %+v", err, files)
		}
		cleanup()
		if read(root, p.ProbeHelper) != string(probeSource) {
			t.Error("the second call's cleanup removed a file the first call wrote")
		}
	})
	t.Run("a different existing helper is refused and nothing of this call is left", func(t *testing.T) {
		root, in := probeProject(t)
		cfgPath := filepath.Join(root, filepath.FromSlash(p.ProbeConfig))
		if err := os.WriteFile(cfgPath, []byte(`{"origin":"http://example.com"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := WriteProbeFiles(root, in)
		if !errors.Is(err, ErrProbeExists) {
			t.Fatalf("err = %v, want ErrProbeExists", err)
		}
		if _, serr := os.Lstat(filepath.Join(root, filepath.FromSlash(p.ProbeHelper))); serr == nil {
			t.Error("probe.py, written by the failed call, was left behind")
		}
		if got := read(root, p.ProbeConfig); got != `{"origin":"http://example.com"}` {
			t.Errorf("the conflicting file was changed: %q", got)
		}
	})
	t.Run("no run folder is refused", func(t *testing.T) {
		_, in := probeProject(t)
		if _, _, err := WriteProbeFiles(t.TempDir(), in); !errors.Is(err, ErrProbeRun) {
			t.Errorf("err = %v, want ErrProbeRun", err)
		}
	})
	t.Run("a link in place of the helper is not followed", func(t *testing.T) {
		root, in := probeProject(t)
		outside := filepath.Join(t.TempDir(), "victim.txt")
		if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, filepath.FromSlash(p.ProbeHelper))); err != nil {
			t.Skipf("no symlinks here: %v", err)
		}
		if _, _, err := WriteProbeFiles(root, in); !errors.Is(err, ErrProbeExists) {
			t.Errorf("err = %v, want ErrProbeExists", err)
		}
		if b, _ := os.ReadFile(outside); string(b) != "keep" {
			t.Errorf("the write went through the link: %q", b)
		}
	})
}

// facts writes the helper files and a log into a fresh project and returns the
// run and the project.
func probeFactsProject(t *testing.T, log string) (string, Run) {
	t.Helper()
	root, in := probeProject(t)
	files, _, err := WriteProbeFiles(root, in)
	if err != nil {
		t.Fatal(err)
	}
	if log != "" {
		writeProjectFile(t, root, secassess.ResultPaths(svcRun).ProbeLog, log)
	}
	return root, Run{ID: svcRun, Helper: secassess.HelperOn, HelperSHA: files.Helper, ConfigSHA: files.Config}
}

func TestReadProbeFacts(t *testing.T) {
	p := secassess.ResultPaths(svcRun)
	line := func(n string) string {
		return `{"v":1,"id":"p` + n + `","ts":"2026-11-14T10:00:00.000Z","role":"control","wstg":"ATHN","account":"","note":"","method":"GET","path":"/","req_headers":[],"req_body_bytes":0,"req_body_excerpt":"","sent":true,"refused":"","error":"","status":200,"resp_headers":[],"body_bytes":2,"body_truncated":false,"body_excerpt":"ok","ms":3,"hops":0,"redirect_to":"","redirect_blocked":false,"cost":1}` + "\n"
	}
	t.Run("a run with no helper reads nothing", func(t *testing.T) {
		root, _ := probeFactsProject(t, line("1"))
		for _, mode := range []string{"", secassess.HelperOff, secassess.HelperWithheld} {
			f := ReadProbeFacts(root, Run{ID: svcRun, Helper: mode})
			if f.Mode != mode || f.HelperHave != "" || f.LogState != "" || len(f.Log.Records) != 0 || f.HelperState() != secassess.HelperNotChecked {
				t.Errorf("mode %q: facts = %+v", mode, f)
			}
		}
	})
	t.Run("an intact helper and a log that reads like the helper's", func(t *testing.T) {
		root, run := probeFactsProject(t, line("1")+line("2"))
		f := ReadProbeFacts(root, run)
		if f.HelperState() != secassess.HelperIntact || f.LogState != secassess.LogFileOK || len(f.Log.Records) != 2 || f.Log.Problem != "" {
			t.Fatalf("facts = %+v", f)
		}
	})
	rows := []struct {
		name   string
		mutate func(t *testing.T, root string)
		helper string
		log    string
		reason string
	}{
		{"a changed helper", func(t *testing.T, root string) {
			writeProjectFile(t, root, p.ProbeHelper, string(probeSource)+"\n# edited\n")
		}, secassess.HelperChanged, secassess.LogFileOK, ""},
		{"a changed settings file", func(t *testing.T, root string) {
			writeProjectFile(t, root, p.ProbeConfig, `{"origin":"http://localhost:1"}`)
		}, secassess.HelperChanged, secassess.LogFileOK, ""},
		{"a helper over the read cap", func(t *testing.T, root string) {
			writeProjectFile(t, root, p.ProbeHelper, strings.Repeat("#", maxProbeHelperBytes+1))
		}, secassess.HelperChanged, secassess.LogFileOK, ""},
		{"a removed helper", func(t *testing.T, root string) {
			_ = os.Remove(filepath.Join(root, filepath.FromSlash(p.ProbeHelper)))
		}, secassess.HelperMissing, secassess.LogFileOK, ""},
		{"no log yet", func(t *testing.T, root string) {
			_ = os.Remove(filepath.Join(root, filepath.FromSlash(p.ProbeLog)))
		}, secassess.HelperIntact, secassess.LogFileAbsent, ""},
		{"a log that is a folder", func(t *testing.T, root string) {
			_ = os.Remove(filepath.Join(root, filepath.FromSlash(p.ProbeLog)))
			if err := os.Mkdir(filepath.Join(root, filepath.FromSlash(p.ProbeLog)), 0o755); err != nil {
				t.Fatal(err)
			}
		}, secassess.HelperIntact, secassess.LogFileUnreadable, ""},
		{"a log with a removed line", func(t *testing.T, root string) {
			writeProjectFile(t, root, p.ProbeLog, line("1")+line("3"))
		}, secassess.HelperIntact, secassess.LogFileOK, secassess.LogBadID},
		{"a line that is not a record", func(t *testing.T, root string) {
			writeProjectFile(t, root, p.ProbeLog, line("1")+"{\"hello\":1}\n")
		}, secassess.HelperIntact, secassess.LogFileOK, secassess.LogBadLine},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			root, run := probeFactsProject(t, line("1")+line("2"))
			tc.mutate(t, root)
			f := ReadProbeFacts(root, run)
			if f.HelperState() != tc.helper || f.LogState != tc.log || f.Log.Problem != tc.reason {
				t.Errorf("helper %s, log %s, problem %q; want %s, %s, %q", f.HelperState(), f.LogState, f.Log.Problem, tc.helper, tc.log, tc.reason)
			}
		})
	}
	t.Run("a torn last line is read again once", func(t *testing.T) {
		root, run := probeFactsProject(t, line("1"))
		full := line("2")
		logPath := filepath.Join(root, filepath.FromSlash(p.ProbeLog))
		// The helper is mid-append: half of the second line is there.
		writeProjectFile(t, root, p.ProbeLog, line("1")+full[:len(full)/2])
		old := probeRetryWait
		probeRetryWait = 300 * time.Millisecond
		defer func() { probeRetryWait = old }()
		done := make(chan struct{})
		go func() {
			time.Sleep(60 * time.Millisecond)
			_ = os.WriteFile(logPath, []byte(line("1")+full), 0o600)
			close(done)
		}()
		f := ReadProbeFacts(root, run)
		<-done
		if f.LogState != secassess.LogFileOK || f.Log.Problem != "" || len(f.Log.Records) != 2 {
			t.Fatalf("facts after the retry = %+v", f)
		}
	})
	t.Run("a log that stays torn is inconsistent, read twice at most", func(t *testing.T) {
		root, run := probeFactsProject(t, line("1")+line("2")[:40])
		old := probeRetryWait
		probeRetryWait = time.Millisecond
		defer func() { probeRetryWait = old }()
		f := ReadProbeFacts(root, run)
		if f.Log.Problem != secassess.LogBadLine {
			t.Fatalf("problem %q", f.Log.Problem)
		}
	})
	t.Run("a log over its cap is not read", func(t *testing.T) {
		root, run := probeFactsProject(t, "")
		fh, err := os.Create(filepath.Join(root, filepath.FromSlash(p.ProbeLog)))
		if err != nil {
			t.Fatal(err)
		}
		if err := fh.Truncate(secassess.MaxProbeLogBytes + 1); err != nil {
			t.Fatal(err)
		}
		_ = fh.Close()
		f := ReadProbeFacts(root, run)
		if f.LogState != secassess.LogFileTooLarge || len(f.Log.Records) != 0 {
			t.Errorf("facts = %+v", f.LogState)
		}
	})
	t.Run("no recorded hashes read as missing", func(t *testing.T) {
		root, run := probeFactsProject(t, line("1"))
		run.HelperSHA, run.ConfigSHA = "", ""
		if got := ReadProbeFacts(root, run).HelperState(); got != secassess.HelperMissing {
			t.Errorf("state = %s", got)
		}
	})
}

// TestProbesRecordFitsItsCap: a stored copy over the side file's cap drops
// cited records from the end and says so; one that fits is untouched.
func TestProbesRecordFitsItsCap(t *testing.T) {
	rec := ProbesRecord{Schema: ProbesSchema, RunID: svcRun}
	for i := 0; i < 40; i++ {
		rec.Probes = append(rec.Probes, secassess.ProbeRecord{ID: "p" + string(rune('a'+i%26)), BodyExcerpt: strings.Repeat("x", 1000)})
	}
	rec.Cited = len(rec.Probes)
	whole, out := fitProbes(rec, 1<<20)
	if whole == nil || out.Truncated || len(out.Probes) != 40 {
		t.Fatalf("a record under the cap changed: %d probes, truncated %v", len(out.Probes), out.Truncated)
	}
	small, out := fitProbes(rec, 12<<10)
	if small == nil || len(small) > 12<<10 || !out.Truncated || len(out.Probes) == 0 || len(out.Probes) >= 40 {
		t.Fatalf("fit = %d bytes, %d probes, truncated %v", len(small), len(out.Probes), out.Truncated)
	}
	if out.Cited != 40 {
		t.Errorf("Cited = %d: the count of what the model cites must not follow what was kept", out.Cited)
	}
	if b, _ := fitProbes(rec, 10); b != nil {
		t.Errorf("a cap no record fits under produced %d bytes", len(b))
	}
}

// pentestWithEvidence is svcPentest with the finding's evidence, indicator and a
// coverage row that cites the same two requests, for the target at url.
func pentestWithEvidence(t *testing.T, url string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(svcPentest, "http://127.0.0.1:3000/", url)), &m); err != nil {
		t.Fatal(err)
	}
	m["coverage"] = []any{map[string]any{"category": "ATHN", "status": "tested", "probes": []any{"p1", "p2"}, "notes": "Tried the login."}}
	f := m["findings"].([]any)[0].(map[string]any)
	f["evidence"] = []any{"p1", "p2"}
	f["indicator"] = map[string]any{"control": "p1", "attack": "p2", "when": map[string]any{"status": 200, "body_contains": []any{"hello"}}}
	f["reproduction"] = []any{map[string]any{"step": "Send the attack request", "request": map[string]any{"method": "GET", "path": "/ok"}}}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestValidateRunWithTheRealHelper runs the helper the service wrote, with a real
// Python, against a loopback server, then validates a model that cites its log:
// the whole path the plan draws, from the written files to the evidence word.
func TestValidateRunWithTheRealHelper(t *testing.T) {
	probeHelperPython(t) // skips without a python 3.8+
	srv := newProbeHelperServer(t)
	root := t.TempDir()
	writeAPIProject(t, root)
	if _, err := PrepareRunDir(root, svcRun); err != nil {
		t.Fatal(err)
	}
	target := mustTarget(t, srv.URL+"/")
	files, _, err := WriteProbeFiles(root, ProbeInput{RunID: svcRun, Target: target, Budget: 50, PaceRPS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	p := secassess.ResultPaths(svcRun)
	hr := &probeHelperRun{t: t, py: probeHelperPython(t), dir: filepath.Join(root, filepath.FromSlash(p.Dir)), srv: srv}
	if out := hr.probe("GET", "/default", "--role", "control", "--wstg", "ATHN"); out.Exit != 0 {
		t.Fatalf("control: %+v", out)
	}
	if out := hr.probe("GET", "/ok", "--role", "attack", "--wstg", "ATHN"); out.Exit != 0 {
		t.Fatalf("attack: %+v", out)
	}
	run := Run{
		ID: svcRun, Kind: "pentest_local", Contract: string(secassess.ContractPentest), Phase: PhaseStarted, Target: target.String(),
		EndedAt: modelRun(secassess.ContractPentest, true).EndedAt, Helper: secassess.HelperOn, HelperSHA: files.Helper, ConfigSHA: files.Config,
	}
	writeModel(t, root, pentestWithEvidence(t, target.String()))
	side := newSide(t)
	validate := func() ModelRecord {
		t.Helper()
		in := validateOpts(root, run, false)
		in.Options.Redact = func(s string) string { return strings.ReplaceAll(s, "hello", "[REDACTED]") }
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil || rec.Result.PT == nil {
			t.Fatalf("validate: %v %+v", err, rec.Result.Report)
		}
		return rec
	}
	finding := func(rec ModelRecord) secassess.PTFinding { return rec.Result.PT.Findings[0] }

	t.Run("an intact helper and its log back the finding", func(t *testing.T) {
		rec := validate()
		f := finding(rec)
		ev := rec.Result.Report.Evidence
		if f.EvidenceState != secassess.EvidenceLogged || f.EvidenceReason != "" {
			t.Fatalf("finding is %q (%q): %+v", f.EvidenceState, f.EvidenceReason, ev)
		}
		if ev == nil || ev.Helper != secassess.HelperIntact || ev.Log != secassess.LogFileOK || ev.Records != 2 || ev.Sent != 2 || ev.Requests != 2 || ev.Logged != 1 {
			t.Fatalf("evidence report = %+v", ev)
		}
		stored, ok := ReadProbes(side, svcRun)
		if !ok || stored.Records != 2 || stored.Cited != 2 || len(stored.Probes) != 2 || stored.Truncated {
			t.Fatalf("stored probes = %+v %v", stored, ok)
		}
		if stored.Probes[0].ID != "p1" || stored.Probes[1].ID != "p2" || stored.Probes[1].Path != "/ok" || stored.Probes[1].V != 0 {
			t.Errorf("stored probes = %+v", stored.Probes)
		}
		if strings.Contains(stored.Probes[1].BodyExcerpt, "hello") || !strings.Contains(stored.Probes[1].BodyExcerpt, "[REDACTED]") {
			t.Errorf("the stored excerpt was not redacted again: %q", stored.Probes[1].BodyExcerpt)
		}
	})
	t.Run("an edited helper makes every finding read No log", func(t *testing.T) {
		writeProjectFile(t, root, p.ProbeHelper, string(probeSource)+"\n# edited by the agent\n")
		rec := validate()
		f := finding(rec)
		if f.EvidenceState != secassess.EvidenceUnlogged || f.EvidenceReason != secassess.ReasonHelperChanged {
			t.Fatalf("finding is %q (%q)", f.EvidenceState, f.EvidenceReason)
		}
		if stored, _ := ReadProbes(side, svcRun); len(stored.Probes) != 0 {
			t.Errorf("a changed helper's log was stored: %d records", len(stored.Probes))
		}
		writeProjectFile(t, root, p.ProbeHelper, string(probeSource)) // restored
	})
	t.Run("a hand-written log of the right shape is not told apart from the helper's", func(t *testing.T) {
		// The documented limit: the log is a file the agent can write. A forged
		// log that keeps the helper's structure and an intact helper reads as
		// matching; this test pins that the plan's words (Helper log matches,
		// never confirmed) are the honest ones, and that nothing else claims more.
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p.ProbeLog)))
		if err != nil {
			t.Fatal(err)
		}
		forged := strings.ReplaceAll(string(raw), "default", "FORGED")
		writeProjectFile(t, root, p.ProbeLog, forged)
		rec := validate()
		if f := finding(rec); f.EvidenceState != secassess.EvidenceLogged {
			t.Fatalf("a well-formed forged log read %q (%q): if this ever fails the plan's honest-limit text changes", f.EvidenceState, f.EvidenceReason)
		}
	})
	t.Run("a hand-written log that breaks the helper's structure is caught", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p.ProbeLog)))
		if err != nil {
			t.Fatal(err)
		}
		first, _, _ := strings.Cut(string(raw), "\n")
		writeProjectFile(t, root, p.ProbeLog, first+"\n"+`{"id":"p2","status":200}`+"\n")
		f := finding(validate())
		if f.EvidenceState != secassess.EvidenceUnlogged || f.EvidenceReason != secassess.ReasonLogInconsistent {
			t.Fatalf("finding is %q (%q)", f.EvidenceState, f.EvidenceReason)
		}
	})
}
