package secassesssvc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeHelperHiddenNote: when a response holds a value the log will keep as
// [REDACTED], the helper prints ONE line on stderr that names it and says what to
// write in indicator.when. It prints it once per header name and once for the body
// per log, never per request, never the value itself, and the record and stdout
// are the same as without the note. The note costs the prompt nothing.
func TestProbeHelperHiddenNote(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	steps := []struct {
		name     string
		args     []string
		names    []string // what the note names; nil: no note at all
		leaks    []string // texts the note must not contain
		notNamed []string
	}{
		{"a response with nothing to hide", []string{"GET", "/ok"}, nil, nil, nil},
		{
			"a cookie and an api key header",
			[]string{"GET", "/cookie"},
			[]string{"Set-Cookie", "X-Api-Key"},
			[]string{probeHelperSessionID, "k-0123456789"},
			[]string{"the body"},
		},
		{"the same headers again: no second note", []string{"GET", "/cookie"}, nil, nil, nil},
		{
			"a body with a password",
			[]string{"GET", "/pw"},
			[]string{"the body"},
			[]string{probeHelperPassword},
			[]string{"Set-Cookie"},
		},
		{"another such body: the body was named already", []string{"GET", "/pw"}, nil, nil, nil},
		{
			"new header names only",
			[]string{"GET", "/hdrs"},
			[]string{"X-Access-Token", "Api-Key", "X-Session"},
			[]string{"opaquetokenvalue123456", "topsecretkeyvalue1", "mysessionvalue12345"},
			[]string{"Www-Authenticate", "Access-Control-Allow-Credentials", "X-Request-Id", "Set-Cookie"},
		},
		{"a marker the server sent itself is not a hidden value", []string{"GET", "/marked"}, nil, nil, nil},
		{
			"six new names are four and a count",
			[]string{"GET", "/many"},
			[]string{"X-Token-1", "X-Token-2", "X-Token-3", "X-Token-4", "and 2 more"},
			[]string{"opaquevalue1"},
			[]string{"X-Token-5", "X-Token-6"},
		},
	}
	for _, st := range steps {
		before := len(run.log())
		out := run.probe(st.args...)
		if out.Exit != 0 {
			t.Fatalf("%s: exit %d: %s", st.name, out.Exit, out.Stderr)
		}
		if len(run.log()) != before+1 {
			t.Fatalf("%s: the log did not grow by one record", st.name)
		}
		if st.names == nil {
			if out.Stderr != "" {
				t.Errorf("%s: stderr %q, want none", st.name, out.Stderr)
			}
			continue
		}
		line := strings.TrimRight(strings.ReplaceAll(out.Stderr, "\r\n", "\n"), "\n")
		if strings.Contains(line, "\n") || !strings.HasPrefix(line, "note: the log keeps [REDACTED]") || len(line) > 220 {
			t.Errorf("%s: the note is not one short line: %q", st.name, out.Stderr)
		}
		for _, w := range append([]string{"indicator.when", "never the value"}, st.names...) {
			if !strings.Contains(line, w) {
				t.Errorf("%s: the note %q does not say %q", st.name, line, w)
			}
		}
		for _, w := range append(append([]string{}, st.leaks...), st.notNamed...) {
			if strings.Contains(line, w) {
				t.Errorf("%s: the note %q names or leaks %q", st.name, line, w)
			}
		}
	}
	// The record is the one there would be without a note: it holds the marker and
	// never the value; stdout still shows the response as it came; a repeated
	// request prints nothing on stderr.
	recs := run.log()
	if !strings.Contains(fmt.Sprint(recs[1].RespHeaders), "[REDACTED]") || strings.Contains(run.rawLog(), probeHelperSessionID) {
		t.Errorf("the log holds the value or lacks the marker: %+v", recs[1])
	}
	if out := run.probe("GET", "/cookie"); !strings.Contains(out.Stdout, "sid="+probeHelperSessionID) || out.Stderr != "" {
		t.Errorf("stdout must show the real cookie and stderr stay empty: %q / %q", out.Stdout, out.Stderr)
	}

	// The Python API says the same through the key "hidden", and an unreadable line
	// in the log (one the agent edited by hand) does not stop it.
	api := newProbeHelperRun(t, probeHelperOpts{})
	if err := os.WriteFile(filepath.Join(api.dir, "probes.jsonl"), []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "from probe import request\nfor path in ('/ok', '/cookie', '/cookie', '/pw'):\n    print(path, request('GET', path)['hidden'])\n"
	path := filepath.Join(api.dir, "try_probe.py")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := api.py3(path, api.dir)
	if err != nil || res.Exit != 0 {
		t.Fatalf("exit %d, err %v, stderr %q", res.Exit, err, res.Stderr)
	}
	want := "/ok []\n/cookie ['Set-Cookie', 'X-Api-Key']\n/cookie []\n/pw ['the body']\n"
	if got := strings.ReplaceAll(res.Stdout, "\r\n", "\n"); got != want || res.Stderr != "" {
		t.Errorf("hidden through the API = %q (stderr %q), want %q", got, res.Stderr, want)
	}
}
