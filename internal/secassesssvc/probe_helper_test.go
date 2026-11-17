package secassesssvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The tests in this file run the embedded request helper (probe/probe.py)
// with a real Python 3 against an httptest server on loopback. They skip when
// no python3.8+ is installed. The record type below is local on purpose: the
// helper's log format is checked here against the written spec, not against
// the Go types of the pure core.

const (
	probeHelperRunID    = "0123456789abcdef"
	probeHelperTSLayout = "2006-01-02T15:04:05.000Z"
)

var probeHelperKeys = []string{
	"v", "id", "ts", "role", "wstg", "account", "note", "method", "path", "req_headers",
	"req_body_bytes", "req_body_excerpt", "sent", "refused", "error", "status", "resp_headers",
	"body_bytes", "body_truncated", "body_excerpt", "ms", "hops", "redirect_to", "redirect_blocked", "cost",
}

type probeHelperHdr struct {
	N string `json:"n"`
	V string `json:"v"`
}

type probeHelperRec struct {
	V               int              `json:"v"`
	ID              string           `json:"id"`
	TS              string           `json:"ts"`
	Role            string           `json:"role"`
	WSTG            string           `json:"wstg"`
	Account         string           `json:"account"`
	Note            string           `json:"note"`
	Method          string           `json:"method"`
	Path            string           `json:"path"`
	ReqHeaders      []probeHelperHdr `json:"req_headers"`
	ReqBodyBytes    int              `json:"req_body_bytes"`
	ReqBodyExcerpt  string           `json:"req_body_excerpt"`
	Sent            bool             `json:"sent"`
	Refused         string           `json:"refused"`
	Error           string           `json:"error"`
	Status          int              `json:"status"`
	RespHeaders     []probeHelperHdr `json:"resp_headers"`
	BodyBytes       int              `json:"body_bytes"`
	BodyTruncated   bool             `json:"body_truncated"`
	BodyExcerpt     string           `json:"body_excerpt"`
	MS              int              `json:"ms"`
	Hops            int              `json:"hops"`
	RedirectTo      string           `json:"redirect_to"`
	RedirectBlocked bool             `json:"redirect_blocked"`
	Cost            int              `json:"cost"`
	// Replay is on a record of a retest's replayed request only (probe.py --replay).
	Replay string `json:"replay,omitempty"`
}

type probeHelperOut struct {
	Exit   int
	Stdout string
	Stderr string
}

// ---- interpreter ------------------------------------------------------------

var (
	probeHelperPyOnce sync.Once
	probeHelperPyArgv []string
)

// probeHelperPython finds a working Python 3.8+ (python3, then python, then
// py -3; the Windows Store stub named python3 fails the version probe and is
// skipped over) or skips the test.
func probeHelperPython(t testing.TB) []string {
	t.Helper()
	probeHelperPyOnce.Do(func() {
		for _, cand := range [][]string{{"python3"}, {"python"}, {"py", "-3"}} {
			if _, err := exec.LookPath(cand[0]); err != nil {
				continue
			}
			args := append(append([]string{}, cand[1:]...), "-c", "import sys; assert sys.version_info >= (3, 8)")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := exec.CommandContext(ctx, cand[0], args...).Run()
			cancel()
			if err == nil {
				probeHelperPyArgv = cand
				return
			}
		}
	})
	if probeHelperPyArgv == nil {
		t.Skip("no working python 3.8+ (python3, python or py -3) on PATH")
	}
	return probeHelperPyArgv
}

func probeHelperSource(t testing.TB) []byte {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("probe", "probe.py"))
	if err != nil {
		t.Fatalf("read embedded helper: %v", err)
	}
	return src
}

// ---- target server ----------------------------------------------------------

type probeHelperSeen struct {
	Method string
	URI    string
	Host   string
	Body   string
	Header http.Header
}

type probeHelperServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []probeHelperSeen
}

func (s *probeHelperServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func (s *probeHelperServer) at(i int) probeHelperSeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < 0 || i >= len(s.seen) {
		return probeHelperSeen{}
	}
	return s.seen[i]
}

const (
	probeHelperJWT       = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.c2lnbmF0dXJlLWZvci10ZXN0cw"
	probeHelperGHToken   = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	probeHelperAWSKey    = "AKIA" + "IOSFODNN7EXAMPLE"
	probeHelperSKKey     = "sk-" + "abcdefghijklmnopqrstuvwxyz0123"
	probeHelperSlackTok  = "xoxb-" + "1234567890-abcdefghijkl"
	probeHelperPEM       = "-----BEGIN " + "PRIVATE KEY-----\nMIIFAKEFAKEFAKEFAKE\n-----END " + "PRIVATE KEY-----"
	probeHelperPassword  = "hunter2hunter2"
	probeHelperSessionID = "abc123def456"
)

func newProbeHelperServer(t testing.TB, useTLS ...bool) *probeHelperServer {
	s := &probeHelperServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		s.mu.Lock()
		s.seen = append(s.seen, probeHelperSeen{Method: r.Method, URI: r.RequestURI, Host: r.Host, Body: string(body), Header: r.Header.Clone()})
		s.mu.Unlock()
		redirect := func(code int, loc string) {
			w.Header().Set("Location", loc)
			w.WriteHeader(code)
		}
		switch p := r.URL.Path; {
		case p == "/ok":
			w.Header().Set("X-Test", "1")
			fmt.Fprint(w, "hello")
		case p == "/big":
			w.Write(bytes.Repeat([]byte("a"), 200<<10))
		case p == "/exact":
			w.Write(bytes.Repeat([]byte("c"), 65536))
		case p == "/huge":
			w.Write(bytes.Repeat([]byte("b"), 3<<19))
		case p == "/utf8":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprint(w, "h\u00e9llo \u20ac \U0001F600")
		case p == "/cookie":
			w.Header().Add("Set-Cookie", "sid="+probeHelperSessionID+"; Path=/; HttpOnly; SameSite=Lax")
			w.Header().Add("Set-Cookie", "theme=dark; Path=/; Secure")
			w.Header().Set("X-Api-Key", "k-0123456789")
			fmt.Fprint(w, "cookies")
		case p == "/jwt":
			fmt.Fprintf(w, `{"data":"%s","ok":true}`, probeHelperJWT)
		case p == "/pw":
			fmt.Fprintf(w, `{"user":"bob","password":"%s","token":"short"}`, probeHelperPassword)
		case p == "/many":
			for i := 1; i <= 6; i++ {
				w.Header().Set(fmt.Sprintf("X-Token-%d", i), "opaquevalue"+strconv.Itoa(i))
			}
			fmt.Fprint(w, "many")
		case p == "/marked":
			w.Header().Set("X-Token", "[REDACTED]")
			fmt.Fprint(w, `{"note":"[REDACTED]"}`)
		case p == "/hdrs":
			w.Header().Set("X-Access-Token", "opaquetokenvalue123456")
			w.Header().Set("Api-Key", "topsecretkeyvalue1")
			w.Header().Set("X-Session", "mysessionvalue12345")
			w.Header().Set("Www-Authenticate", `Basic realm="app"`)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("X-Request-Id", "req-1")
			fmt.Fprint(w, "headers")
		case p == "/straddle":
			fmt.Fprint(w, strings.Repeat("x", 1010)+" "+probeHelperGHToken+" tail")
		case p == "/secrets":
			fmt.Fprintf(w, "aws %s openai %s slack %s gh %s pem %s end", probeHelperAWSKey, probeHelperSKKey, probeHelperSlackTok, probeHelperGHToken, probeHelperPEM)
		case p == "/text":
			fmt.Fprint(w, "task-abcdefghijklmnopqrstuvwxyz is a word, not a key")
		case p == "/redir":
			redirect(302, "/ok")
		case p == "/redir-ext":
			redirect(302, "http://evil.example/x")
		case p == "/redir-sr":
			redirect(302, "//evil.example/x")
		case p == "/loop":
			redirect(302, "/loop")
		case p == "/see-other":
			redirect(303, "/echo")
		case p == "/temp":
			redirect(307, "/echo")
		case strings.HasPrefix(p, "/status/"):
			code, _ := strconv.Atoi(strings.TrimPrefix(p, "/status/"))
			w.WriteHeader(code)
			fmt.Fprint(w, "status body")
		case p == "/delay":
			time.Sleep(100 * time.Millisecond)
			fmt.Fprint(w, "late")
		case p == "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case p == "/echo":
			fmt.Fprintf(w, "echo %s %s", r.Method, body)
		case p == "/wide":
			for i := 0; i < 45; i++ {
				w.Header().Set(fmt.Sprintf("X-Wide-%02d", i), strings.Repeat("\u00e9", 300))
			}
			fmt.Fprint(w, strings.Repeat("\U0001F600", 20000))
		default:
			fmt.Fprint(w, "default")
		}
	})
	if len(useTLS) > 0 && useTLS[0] {
		s.Server = httptest.NewTLSServer(handler) // self-signed certificate
	} else {
		s.Server = httptest.NewServer(handler)
	}
	t.Cleanup(s.Close)
	return s
}

// ---- run folder -------------------------------------------------------------

type probeHelperOpts struct {
	cfg     func(map[string]any) // edit the default probe.json
	raw     *string              // probe.json exactly as given
	noFile  bool                 // write no probe.json
	dirName string               // run folder name, default probeHelperRunID
	origin  string               // origin to write, default the server's
	tls     bool                 // serve the target over https with a self-signed certificate
	pace    int                  // pace_rps, default 1000
}

type probeHelperRun struct {
	t   testing.TB
	py  []string
	dir string
	srv *probeHelperServer
}

func newProbeHelperRun(t testing.TB, opts probeHelperOpts) *probeHelperRun {
	t.Helper()
	py := probeHelperPython(t)
	src := probeHelperSource(t)
	if opts.dirName == "" {
		opts.dirName = probeHelperRunID
	}
	srv := newProbeHelperServer(t, opts.tls)
	dir := filepath.Join(t.TempDir(), opts.dirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe.py"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if opts.origin == "" {
		opts.origin = srv.URL
	}
	if opts.pace == 0 {
		opts.pace = 1000
	}
	cfg := map[string]any{"schema": "observer.probe.v1", "run_id": probeHelperRunID, "origin": opts.origin, "budget": 600, "pace_rps": opts.pace, "max_bytes": 65536}
	if opts.cfg != nil {
		opts.cfg(cfg)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts.raw != nil {
		data = []byte(*opts.raw)
	}
	if !opts.noFile {
		if err := os.WriteFile(filepath.Join(dir, "probe.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &probeHelperRun{t: t, py: py, dir: dir, srv: srv}
}

// py3 runs a python script (default probe.py in the run folder) and reports
// its exit status; it never calls t.Fatal so it can run in a goroutine.
func (r *probeHelperRun) py3(script, dir string, args ...string) (probeHelperOut, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	argv := append(append([]string{}, r.py[1:]...), script)
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, r.py[0], argv...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	out := probeHelperOut{Stdout: so.String(), Stderr: se.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		out.Exit = ee.ExitCode()
		err = nil
	}
	return out, err
}

// probe runs `python probe.py args...` in the run folder.
func (r *probeHelperRun) probe(args ...string) probeHelperOut {
	r.t.Helper()
	out, err := r.py3(filepath.Join(r.dir, "probe.py"), r.dir, args...)
	if err != nil {
		r.t.Fatalf("run probe.py %v: %v", args, err)
	}
	return out
}

// log decodes probes.jsonl strictly: every line has exactly the spec's keys,
// LF endings, ASCII only.
func (r *probeHelperRun) log() []probeHelperRec {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.dir, "probes.jsonl"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		r.t.Fatal(err)
	}
	if bytes.IndexByte(raw, '\r') >= 0 {
		r.t.Fatalf("probes.jsonl has CR bytes")
	}
	for _, b := range raw {
		if b >= 0x80 {
			r.t.Fatalf("probes.jsonl is not ASCII-only (ensure_ascii)")
		}
	}
	if len(raw) == 0 {
		return nil
	}
	if raw[len(raw)-1] != '\n' {
		r.t.Fatalf("probes.jsonl does not end with a newline")
	}
	want := append([]string{}, probeHelperKeys...)
	sort.Strings(want)
	var recs []probeHelperRec
	for i, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &keys); err != nil {
			r.t.Fatalf("line %d is not a JSON object: %v: %q", i+1, err, line)
		}
		got := make([]string, 0, len(keys))
		for k := range keys {
			got = append(got, k)
		}
		sort.Strings(got)
		wantLine := want
		if _, has := keys["replay"]; has { // the one key a line may carry beyond the spec's: a replayed request
			wantLine = append(append([]string{}, want...), "replay")
			sort.Strings(wantLine)
		}
		if strings.Join(got, ",") != strings.Join(wantLine, ",") {
			r.t.Fatalf("line %d keys = %v, want %v", i+1, got, wantLine)
		}
		for _, k := range []string{"req_headers", "resp_headers"} {
			if !strings.HasPrefix(string(keys[k]), "[") {
				r.t.Fatalf("line %d: %s is %s, want a list", i+1, k, keys[k])
			}
		}
		var rec probeHelperRec
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			r.t.Fatalf("line %d: %v", i+1, err)
		}
		recs = append(recs, rec)
	}
	return recs
}

func (r *probeHelperRun) rawLog() string {
	b, _ := os.ReadFile(filepath.Join(r.dir, "probes.jsonl"))
	return string(b)
}

func (r *probeHelperRun) last() probeHelperRec {
	r.t.Helper()
	recs := r.log()
	if len(recs) == 0 {
		r.t.Fatal("probes.jsonl is empty")
	}
	return recs[len(recs)-1]
}

func probeHelperWantRefused(t *testing.T, out probeHelperOut, rec probeHelperRec, code string) {
	t.Helper()
	if out.Exit != 3 {
		t.Errorf("exit = %d, want 3 (stdout %q, stderr %q)", out.Exit, out.Stdout, out.Stderr)
	}
	if !strings.Contains(out.Stderr, "("+code+")") {
		t.Errorf("stderr %q does not name %q", out.Stderr, code)
	}
	if rec.Refused != code || rec.Sent || rec.Status != 0 || rec.Cost != 0 || rec.Error != "" || rec.MS != 0 {
		t.Errorf("refused record = %+v, want refused %q, nothing sent", rec, code)
	}
}

func probeHelperClosedOrigin(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "http://" + addr
}

func probeHelperHost(srv *probeHelperServer) string { return strings.TrimPrefix(srv.URL, "http://") }

// ---- (1) log shape, ids, timestamps, exit codes -----------------------------

func TestProbeHelperLogShape(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	tsRE := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	steps := []struct {
		name   string
		args   []string
		exit   int
		logged bool
		check  func(t *testing.T, out probeHelperOut, rec probeHelperRec)
	}{
		{
			"get with every label",
			[]string{"GET", "/ok", "-H", "X-Test: abc", "--role", "attack", "--wstg", "ATHZ", "--account", "alice", "--note", "hi"},
			0, true,
			func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
				first, _, _ := strings.Cut(out.Stdout, "\n")
				if !regexp.MustCompile(`^probe p1 GET /ok -> 200 OK \(\d+ ms, 5 bytes\)$`).MatchString(first) {
					t.Errorf("first stdout line = %q", first)
				}
				if !strings.Contains(out.Stdout, "\nX-Test: 1\n") || !strings.HasSuffix(out.Stdout, "\n\nhello") {
					t.Errorf("stdout = %q, want headers then a blank line then the body", out.Stdout)
				}
				if rec.V != 1 || rec.ID != "p1" || rec.Role != "attack" || rec.WSTG != "ATHZ" || rec.Account != "alice" || rec.Note != "hi" ||
					rec.Method != "GET" || rec.Path != "/ok" || !rec.Sent || rec.Refused != "" || rec.Error != "" || rec.Status != 200 ||
					rec.BodyBytes != 5 || rec.BodyTruncated || rec.BodyExcerpt != "hello" || rec.Hops != 0 || rec.Cost != 1 ||
					rec.RedirectTo != "" || rec.RedirectBlocked || rec.ReqBodyBytes != 0 || rec.ReqBodyExcerpt != "" {
					t.Errorf("record = %+v", rec)
				}
				if len(rec.ReqHeaders) != 1 || rec.ReqHeaders[0] != (probeHelperHdr{"X-Test", "abc"}) {
					t.Errorf("req_headers = %+v", rec.ReqHeaders)
				}
				found := false
				for _, h := range rec.RespHeaders {
					found = found || h == probeHelperHdr{"X-Test", "1"}
				}
				if !found {
					t.Errorf("resp_headers = %+v, want X-Test: 1", rec.RespHeaders)
				}
				seen := run.srv.at(0)
				if seen.Header.Get("X-Test") != "abc" || seen.Host != probeHelperHost(run.srv) {
					t.Errorf("server saw %+v", seen)
				}
			},
		},
		{
			"post with a body",
			[]string{"POST", "/echo", "-H", "Content-Type: text/plain", "-d", `{"a":1}`},
			0, true,
			func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
				if rec.ReqBodyBytes != 7 || rec.ReqBodyExcerpt != `{"a":1}` || rec.BodyExcerpt != `echo POST {"a":1}` {
					t.Errorf("record = %+v", rec)
				}
				if seen := run.srv.at(1); seen.Method != "POST" || seen.Body != `{"a":1}` {
					t.Errorf("server saw %+v", seen)
				}
			},
		},
		{
			"head has no body",
			[]string{"HEAD", "/ok"},
			0, true,
			func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
				if rec.Status != 200 || rec.BodyBytes != 0 || rec.Method != "HEAD" {
					t.Errorf("record = %+v", rec)
				}
			},
		},
		{
			"lower-case method is stored upper-case",
			[]string{"get", "/status/404"},
			0, true,
			func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
				if rec.Method != "GET" || rec.Status != 404 || !strings.Contains(out.Stdout, " -> 404 Not Found (") {
					t.Errorf("record = %+v, stdout %q", rec, out.Stdout)
				}
			},
		},
		{
			"a 500 is still exit 0",
			[]string{"GET", "/status/500", "--timeout", "99"},
			0, true,
			func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
				if rec.Status != 500 || !rec.Sent {
					t.Errorf("record = %+v", rec)
				}
			},
		},
		{
			"non-ascii body is escaped in the log",
			[]string{"GET", "/utf8", "--timeout", "0"},
			0, true,
			func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
				want := "h\u00e9llo \u20ac \U0001F600"
				if rec.BodyExcerpt != want || !strings.HasSuffix(out.Stdout, "\n\n"+want) || rec.BodyBytes != len(want) {
					t.Errorf("excerpt %q, stdout %q", rec.BodyExcerpt, out.Stdout)
				}
			},
		},
		{
			"unknown method is refused",
			[]string{"TRACE", "/ok"},
			3, true,
			func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
				probeHelperWantRefused(t, out, rec, "bad_method")
				if rec.Method != "TRACE" || rec.Path != "/ok" {
					t.Errorf("record = %+v", rec)
				}
			},
		},
		{"usage error logs nothing", []string{"GET"}, 2, false, nil},
		{"bad role is a usage error", []string{"GET", "/ok", "--role", "bogus"}, 2, false, nil},
	}
	lines := 0
	for _, st := range steps {
		out := run.probe(st.args...)
		if out.Exit != st.exit {
			t.Fatalf("%s: exit = %d, want %d (stdout %q, stderr %q)", st.name, out.Exit, st.exit, out.Stdout, out.Stderr)
		}
		recs := run.log()
		if st.logged {
			lines++
		}
		if len(recs) != lines {
			t.Fatalf("%s: %d log lines, want %d", st.name, len(recs), lines)
		}
		if st.check != nil {
			st.check(t, out, recs[len(recs)-1])
		}
	}
	recs := run.log()
	var prev time.Time
	for i, rec := range recs {
		if rec.ID != fmt.Sprintf("p%d", i+1) {
			t.Errorf("line %d id = %q", i+1, rec.ID)
		}
		if !tsRE.MatchString(rec.TS) {
			t.Errorf("line %d ts = %q", i+1, rec.TS)
			continue
		}
		ts, err := time.Parse(probeHelperTSLayout, rec.TS)
		if err != nil || ts.Before(prev) {
			t.Errorf("line %d ts %q not monotonic after %v (%v)", i+1, rec.TS, prev, err)
		}
		prev = ts
	}
}

// ---- (2) target-only --------------------------------------------------------

func TestProbeHelperOffTarget(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	host := probeHelperHost(run.srv)
	rows := []struct{ name, target, code string }{
		{"other host", "http://evil.example/x", "off_target"},
		{"same host other port", "http://127.0.0.1:1/x", "off_target"},
		{"scheme differs", "https://" + host + "/x", "off_target"},
		{"userinfo", "http://user@" + host + "/x", "off_target"},
		{"localhost is not the configured host", strings.Replace(run.srv.URL, "127.0.0.1", "localhost", 1) + "/x", "off_target"},
		{"file scheme", "file:///etc/passwd", "off_target"},
		{"scheme-relative", "//evil.example/x", "bad_path"},
		{"no leading slash", "evil.example/x", "bad_path"},
		{"space", "/a b", "bad_path"},
		{"too long", "/" + strings.Repeat("a", 2048), "bad_path"},
		{"non-ascii", "/caf\u00e9", "bad_path"},
		{"query only", "?x=1", "bad_path"},
	}
	for _, row := range rows {
		out := run.probe("GET", row.target)
		probeHelperWantRefused(t, out, run.last(), row.code)
		if n := run.srv.count(); n != 0 {
			t.Fatalf("%s: server saw %d requests, want 0", row.name, n)
		}
	}
	if recs := run.log(); len(recs) != len(rows) {
		t.Errorf("%d log lines, want one per refusal (%d)", len(recs), len(rows))
	}
	positive := []struct{ name, target, path string }{
		{"absolute url on the origin", run.srv.URL + "/ok?x=1", "/ok?x=1"},
		{"origin without a path", run.srv.URL, "/"},
		{"longest allowed path", "/" + strings.Repeat("a", 2047), "/" + strings.Repeat("a", 2047)},
	}
	for i, row := range positive {
		out := run.probe("GET", row.target)
		rec := run.last()
		if out.Exit != 0 || rec.Path != row.path || !rec.Sent {
			t.Errorf("%s: exit %d, record %+v", row.name, out.Exit, rec)
		}
		if run.srv.count() != i+1 {
			t.Errorf("%s: server saw %d requests", row.name, run.srv.count())
		}
	}
}

// ---- (3) headers ------------------------------------------------------------

func TestProbeHelperHeaders(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, "-H", fmt.Sprintf("X-N%d: v", i))
	}
	refused := []struct {
		name string
		args []string
	}{
		{"host", []string{"-H", "Host: evil.example"}},
		{"host lower case", []string{"-H", "host: evil.example"}},
		{"connection", []string{"-H", "Connection: keep-alive"}},
		{"content-length", []string{"-H", "Content-Length: 5"}},
		{"transfer-encoding", []string{"-H", "Transfer-Encoding: chunked"}},
		{"name with a space", []string{"-H", "Bad Name: x"}},
		{"name with an underscore", []string{"-H", "X_Y: x"}},
		{"no colon", []string{"-H", "NoColon"}},
		{"value with a line break", []string{"-H", "X-A: b\r\nX-B: c"}},
		{"value too long", []string{"-H", "X-Long: " + strings.Repeat("v", 2049)}},
		{"more than 20", many},
	}
	for i, row := range refused {
		out := run.probe(append([]string{"GET", "/ok"}, row.args...)...)
		probeHelperWantRefused(t, out, run.last(), "bad_header")
		if run.srv.count() != 0 {
			t.Fatalf("%s: server saw a request", row.name)
		}
		if len(run.log()) != i+1 {
			t.Fatalf("%s: refusal not logged", row.name)
		}
	}
	out := run.probe("GET", "/ok", "-H", "X-Dup: 1", "-H", "X-Dup: 2", "-H", "Accept-Encoding: gzip", "-H", "User-Agent: probe-test")
	if out.Exit != 0 {
		t.Fatalf("exit = %d: %s", out.Exit, out.Stderr)
	}
	seen := run.srv.at(0)
	if got := seen.Header["X-Dup"]; len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Errorf("X-Dup = %v, want both values in order", got)
	}
	if seen.Header.Get("Accept-Encoding") != "gzip" || seen.Header.Get("User-Agent") != "probe-test" || seen.Host != probeHelperHost(run.srv) {
		t.Errorf("server saw %+v", seen)
	}
	if rec := run.last(); len(rec.ReqHeaders) != 4 || rec.ReqHeaders[0] != (probeHelperHdr{"X-Dup", "1"}) {
		t.Errorf("req_headers = %+v", rec.ReqHeaders)
	}
}

// ---- (4) response body cap and the request body -----------------------------

func TestProbeHelperBodyCap(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name      string
		maxBytes  int
		path      string
		bytes     int
		truncated bool
		excerpt   int
	}{
		{"200 KiB is cut to 64 KiB", 65536, "/big", 65536, true, 1024},
		{"exactly 64 KiB is not truncated", 65536, "/exact", 65536, false, 1024},
		{"a small max_bytes", 100, "/big", 100, true, 100},
		{"max_bytes is clamped to 1 MiB", 5000000, "/huge", 1048576, true, 1024},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			run := newProbeHelperRun(t, probeHelperOpts{cfg: func(c map[string]any) { c["max_bytes"] = row.maxBytes }})
			out := run.probe("GET", row.path)
			rec := run.last()
			if out.Exit != 0 || rec.BodyBytes != row.bytes || rec.BodyTruncated != row.truncated || utf8.RuneCountInString(rec.BodyExcerpt) != row.excerpt {
				t.Errorf("exit %d, body_bytes %d, truncated %v, excerpt %d chars", out.Exit, rec.BodyBytes, rec.BodyTruncated, utf8.RuneCountInString(rec.BodyExcerpt))
			}
			notice := fmt.Sprintf("[body cut at %d bytes]", row.bytes)
			if strings.Contains(out.Stdout, notice) != row.truncated {
				t.Errorf("cut notice present = %v, want %v", !row.truncated, row.truncated)
			}
			if len(out.Stdout) < row.bytes {
				t.Errorf("stdout has %d bytes, want the whole capped body", len(out.Stdout))
			}
		})
	}
}

func TestProbeHelperRequestBody(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	write := func(name string, n int) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, bytes.Repeat([]byte("z"), n), 0o600); err != nil {
			t.Fatal(err)
		}
		return "@" + p
	}
	out := run.probe("POST", "/echo", "-d", write("max.bin", 65536))
	rec := run.last()
	if out.Exit != 0 || rec.ReqBodyBytes != 65536 || utf8.RuneCountInString(rec.ReqBodyExcerpt) != 1024 || len(run.srv.at(0).Body) != 65536 {
		t.Errorf("65536-byte file: exit %d, record %+v", out.Exit, rec)
	}
	out = run.probe("POST", "/echo", "-d", write("big.bin", 65537))
	probeHelperWantRefused(t, out, run.last(), "body_too_large")
	if run.srv.count() != 1 {
		t.Errorf("server saw %d requests, want only the first", run.srv.count())
	}
	out = run.probe("POST", "/echo", "-d", "@"+filepath.Join(t.TempDir(), "missing"))
	if out.Exit != 2 || len(run.log()) != 2 {
		t.Errorf("missing body file: exit %d, %d log lines, want a usage error that logs nothing", out.Exit, len(run.log()))
	}
	out = run.probe("POST", "/echo")
	if out.Exit != 0 || run.srv.at(1).Header.Get("Content-Length") != "0" {
		t.Errorf("empty POST: exit %d, server saw %+v", out.Exit, run.srv.at(1))
	}
}

// ---- (5) redaction ----------------------------------------------------------

func TestProbeHelperRedaction(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	redacted := "[REDACTED]"
	hasHeader := func(hs []probeHelperHdr, n, v string) bool {
		for _, h := range hs {
			if h.N == n && h.V == v {
				return true
			}
		}
		return false
	}
	rows := []struct {
		name  string
		args  []string
		check func(t *testing.T, out probeHelperOut, rec probeHelperRec)
	}{
		{"bearer", []string{"GET", "/ok", "-H", "Authorization: Bearer abcdefghijklmnop0123456789"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if !hasHeader(rec.ReqHeaders, "Authorization", "Bearer "+redacted) {
				t.Errorf("req_headers = %+v", rec.ReqHeaders)
			}
		}},
		{"basic", []string{"GET", "/ok", "-H", "Authorization: Basic dGVzdDp0ZXN0"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if !hasHeader(rec.ReqHeaders, "Authorization", "Basic "+redacted) {
				t.Errorf("req_headers = %+v", rec.ReqHeaders)
			}
		}},
		{"authorization without a scheme", []string{"GET", "/ok", "-H", "Authorization: opaquetokenvalue"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if !hasHeader(rec.ReqHeaders, "Authorization", redacted) {
				t.Errorf("req_headers = %+v", rec.ReqHeaders)
			}
		}},
		{"proxy-authorization", []string{"GET", "/ok", "-H", "Proxy-Authorization: Basic dGVzdDp0ZXN0"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if !hasHeader(rec.ReqHeaders, "Proxy-Authorization", "Basic "+redacted) {
				t.Errorf("req_headers = %+v", rec.ReqHeaders)
			}
		}},
		{"cookie", []string{"GET", "/ok", "-H", "Cookie: a=1; b=two"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if !hasHeader(rec.ReqHeaders, "Cookie", "a="+redacted+"; b="+redacted) {
				t.Errorf("req_headers = %+v", rec.ReqHeaders)
			}
		}},
		{"api key and csrf headers", []string{"GET", "/ok", "-H", "X-Api-Key: k-1234567890", "-H", "X-Csrf-Token: c-1234567890"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if !hasHeader(rec.ReqHeaders, "X-Api-Key", redacted) || !hasHeader(rec.ReqHeaders, "X-Csrf-Token", redacted) {
				t.Errorf("req_headers = %+v", rec.ReqHeaders)
			}
		}},
		{"set-cookie keeps its attributes", []string{"GET", "/cookie"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if !hasHeader(rec.RespHeaders, "Set-Cookie", "sid="+redacted+"; Path=/; HttpOnly; SameSite=Lax") ||
				!hasHeader(rec.RespHeaders, "Set-Cookie", "theme="+redacted+"; Path=/; Secure") || !hasHeader(rec.RespHeaders, "X-Api-Key", redacted) {
				t.Errorf("resp_headers = %+v", rec.RespHeaders)
			}
			if !strings.Contains(out.Stdout, "sid="+probeHelperSessionID) {
				t.Errorf("stdout must show the real cookie: %q", out.Stdout)
			}
		}},
		{"jwt in a body", []string{"GET", "/jwt"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if rec.BodyExcerpt != `{"data":"`+redacted+`","ok":true}` {
				t.Errorf("body_excerpt = %q", rec.BodyExcerpt)
			}
			if !strings.Contains(out.Stdout, probeHelperJWT) {
				t.Errorf("stdout must show the real body")
			}
		}},
		{"password in a json body", []string{"GET", "/pw"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if rec.BodyExcerpt != `{"user":"bob","password":"`+redacted+`","token":"`+redacted+`"}` {
				t.Errorf("body_excerpt = %q (a short value under a keyword goes too)", rec.BodyExcerpt)
			}
		}},
		{"credential header names, request and response", []string{"GET", "/hdrs", "-H", "X-Access-Token: opaquetokenvalue123456", "-H", "X-Session: mysessionvalue12345", "-H", "Api-Key: topsecretkeyvalue1", "-H", "X-Request-Id: r-9"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			for _, n := range []string{"X-Access-Token", "X-Session", "Api-Key"} {
				if !hasHeader(rec.ReqHeaders, n, redacted) {
					t.Errorf("req_headers = %+v, want %s hidden", rec.ReqHeaders, n)
				}
			}
			if !hasHeader(rec.ReqHeaders, "X-Request-Id", "r-9") {
				t.Errorf("req_headers = %+v, an ordinary header must stay", rec.ReqHeaders)
			}
			for _, n := range []string{"X-Access-Token", "X-Session", "Api-Key"} {
				if !hasHeader(rec.RespHeaders, n, redacted) {
					t.Errorf("resp_headers = %+v, want %s hidden", rec.RespHeaders, n)
				}
			}
			for _, kept := range [][2]string{{"Www-Authenticate", `Basic realm="app"`}, {"Access-Control-Allow-Credentials", "true"}, {"X-Request-Id", "req-1"}} {
				if !hasHeader(rec.RespHeaders, kept[0], kept[1]) {
					t.Errorf("resp_headers = %+v, want %s kept", rec.RespHeaders, kept[0])
				}
			}
			if !strings.Contains(out.Stdout, "opaquetokenvalue123456") {
				t.Errorf("stdout must show the real response headers: %q", out.Stdout)
			}
		}},
		{"token straddling the 1024 cut", []string{"GET", "/straddle"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if utf8.RuneCountInString(rec.BodyExcerpt) != 1024 || strings.Contains(rec.BodyExcerpt, "ghp_") || strings.Contains(rec.BodyExcerpt, "ABCDEFGH") || !strings.Contains(rec.BodyExcerpt, redacted) {
				t.Errorf("excerpt has %d characters: %q", utf8.RuneCountInString(rec.BodyExcerpt), rec.BodyExcerpt[max(0, len(rec.BodyExcerpt)-40):])
			}
		}},
		{"token kinds in a body", []string{"GET", "/secrets"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			for _, secret := range []string{probeHelperAWSKey, probeHelperSKKey, probeHelperSlackTok, probeHelperGHToken, "MIIFAKE", "BEGIN PRIVATE"} {
				if strings.Contains(rec.BodyExcerpt, secret) {
					t.Errorf("excerpt still holds %q: %q", secret, rec.BodyExcerpt)
				}
			}
			if strings.Count(rec.BodyExcerpt, redacted) != 5 || !strings.HasSuffix(rec.BodyExcerpt, " end") {
				t.Errorf("body_excerpt = %q, want five redactions and the text around them", rec.BodyExcerpt)
			}
		}},
		{"a word that only contains sk-", []string{"GET", "/text"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if rec.BodyExcerpt != "task-abcdefghijklmnopqrstuvwxyz is a word, not a key" {
				t.Errorf("body_excerpt = %q, want it unchanged", rec.BodyExcerpt)
			}
		}},
		{"token in a note", []string{"GET", "/ok", "--note", "tried " + probeHelperGHToken + " here"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if rec.Note != "tried "+redacted+" here" {
				t.Errorf("note = %q", rec.Note)
			}
		}},
		{"token in a query value", []string{"GET", "/ok?token=abcdefgh12345&q=1"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if rec.Path != "/ok?token="+redacted+"&q=1" {
				t.Errorf("path = %q", rec.Path)
			}
			if got := run.srv.at(run.srv.count() - 1).URI; got != "/ok?token=abcdefgh12345&q=1" {
				t.Errorf("server saw %q, the request itself must not change", got)
			}
		}},
		{"password in a request body", []string{"POST", "/echo", "-d", `{"password":"` + probeHelperPassword + `"}`}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if rec.ReqBodyExcerpt != `{"password":"`+redacted+`"}` || rec.ReqBodyBytes != len(`{"password":"`+probeHelperPassword+`"}`) {
				t.Errorf("req_body_excerpt = %q, bytes %d", rec.ReqBodyExcerpt, rec.ReqBodyBytes)
			}
		}},
		{"nothing to redact", []string{"GET", "/ok?q=short"}, func(t *testing.T, out probeHelperOut, rec probeHelperRec) {
			if rec.Path != "/ok?q=short" || rec.BodyExcerpt != "hello" {
				t.Errorf("record = %+v", rec)
			}
		}},
	}
	for _, row := range rows {
		out := run.probe(row.args...)
		if out.Exit != 0 {
			t.Fatalf("%s: exit %d: %s", row.name, out.Exit, out.Stderr)
		}
		t.Run(row.name, func(t *testing.T) { row.check(t, out, run.last()) })
	}
	raw := run.rawLog()
	for _, secret := range []string{probeHelperJWT, probeHelperGHToken, probeHelperAWSKey, probeHelperSKKey, probeHelperSlackTok, probeHelperPassword, probeHelperSessionID, "abcdefghijklmnop0123456789", "dGVzdDp0ZXN0", "abcdefgh12345", "k-1234567890", "k-0123456789", "opaquetokenvalue", "opaquetokenvalue123456", "mysessionvalue12345", "topsecretkeyvalue1"} {
		if strings.Contains(raw, secret) {
			t.Errorf("probes.jsonl still holds %q", secret)
		}
	}
}

// TestProbeHelperRedactionKeywords: a field named like a credential loses its
// value however short it is, in a query, a form body and a JSON body; a name
// that only contains such a word, and a "code" outside a form field, stay.
func TestProbeHelperRedactionKeywords(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	const r = "[REDACTED]"
	rows := []struct{ name, path, body, wantPath, wantBody string }{
		{name: "key", path: "/ok?key=abc&x=1", wantPath: "/ok?key=" + r + "&x=1"},
		{name: "auth", path: "/ok?auth=zz1", wantPath: "/ok?auth=" + r},
		{name: "code", path: "/ok?code=123&state=s", wantPath: "/ok?code=" + r + "&state=s"},
		{name: "pwd", path: "/ok?pwd=ab", wantPath: "/ok?pwd=" + r},
		{name: "pass", path: "/ok?pass=a", wantPath: "/ok?pass=" + r},
		{name: "otp", path: "/ok?otp=1234", wantPath: "/ok?otp=" + r},
		{name: "signature", path: "/ok?signature=xyz", wantPath: "/ok?signature=" + r},
		{name: "access key and jwt", path: "/ok?access_key=a&jwt=b", wantPath: "/ok?access_key=" + r + "&jwt=" + r},
		{name: "a user_sid field", path: "/ok?user_sid=5", wantPath: "/ok?user_sid=" + r},
		{name: "form body", path: "/echo", body: "user=bob&pass=ab&otp=1", wantPath: "/echo", wantBody: "user=bob&pass=" + r + "&otp=" + r},
		{name: "json password under 6 characters", path: "/echo", body: `{"password":"abc12"}`, wantPath: "/echo", wantBody: `{"password":"` + r + `"}`},
		{name: "json key and auth", path: "/echo", body: `{"key":"k","auth":"a"}`, wantPath: "/echo", wantBody: `{"key":"` + r + `","auth":"` + r + `"}`},
		{name: "keyboard is not a key", path: "/ok?keyboard=layout", wantPath: "/ok?keyboard=layout"},
		{name: "author is not auth", path: "/ok?author=jane", wantPath: "/ok?author=jane"},
		{name: "encode is not code", path: "/ok?encode=abc", wantPath: "/ok?encode=abc"},
		{name: "monkey is not key", path: "/ok?monkey=banana", wantPath: "/ok?monkey=banana"},
		{name: "an error code in json stays", path: "/echo", body: `{"code":"USER_EXISTS"}`, wantPath: "/echo", wantBody: `{"code":"USER_EXISTS"}`},
		{name: "a code in prose stays", path: "/echo", body: "status code: 404", wantPath: "/echo", wantBody: "status code: 404"},
	}
	for _, row := range rows {
		args := []string{"GET", row.path}
		if row.body != "" {
			args = []string{"POST", row.path, "-d", row.body}
		}
		if out := run.probe(args...); out.Exit != 0 {
			t.Fatalf("%s: exit %d: %s", row.name, out.Exit, out.Stderr)
		}
		rec := run.last()
		if rec.Path != row.wantPath || rec.ReqBodyExcerpt != row.wantBody {
			t.Errorf("%s: path %q body %q, want %q and %q", row.name, rec.Path, rec.ReqBodyExcerpt, row.wantPath, row.wantBody)
		}
	}
}

// TestProbeHelperCredentialHeaderNames pins the header-name rule of probe.py to
// the Go side (secassess.CredentialHeaderName): the pattern and the exceptions
// are the same words, and the helper stores a value as [REDACTED] exactly for
// the names Go says are credentials.
func TestProbeHelperCredentialHeaderNames(t *testing.T) {
	t.Parallel()
	src := string(probeHelperSource(t))
	pat := regexp.MustCompile(`_CRED_NAME = re\.compile\(r"([^"]*)"`).FindStringSubmatch(src)
	if pat == nil || pat[1] != secassess.CredentialHeaderPattern {
		t.Fatalf("probe.py _CRED_NAME = %v, want the pattern %q of secassess.CredentialHeaderPattern", pat, secassess.CredentialHeaderPattern)
	}
	exc := regexp.MustCompile(`_NOT_CRED = \(([^)]*)\)`).FindStringSubmatch(src)
	if exc == nil {
		t.Fatal("probe.py has no _NOT_CRED")
	}
	var got []string
	for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(exc[1], -1) {
		got = append(got, q[1])
	}
	if strings.Join(got, ",") != strings.Join(secassess.NotCredentialHeaders, ",") {
		t.Fatalf("probe.py _NOT_CRED = %v, want %v", got, []string(secassess.NotCredentialHeaders))
	}
	names := []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "Api-Key", "X-Access-Token", "X-Session",
		"X-Session-Id", "X-Auth-Token", "X-Csrf-Token", "X-XSRF-TOKEN", "X-Signature", "X-Hub-Signature-256",
		"X-Amz-Security-Token", "X-OTP", "Sec-WebSocket-Key", "Idempotency-Key", "X-Jwt-Assertion", "X-Hmac",
		"Content-Type", "Cache-Control", "Content-Security-Policy", "Location", "Keep-Alive", "Content-Disposition",
		"X-Request-Id", "X-Error-Code", "WWW-Authenticate", "Proxy-Authenticate", "Access-Control-Allow-Credentials",
	}
	run := newProbeHelperRun(t, probeHelperOpts{})
	script := "import json, sys\nsys.path.insert(0, '.')\nimport probe\nout = {}\nfor n in json.loads(sys.argv[1]):\n    out[n] = [probe.credential_header(n), probe.redact_header(n, 'plainvalue123')]\nprint(json.dumps(out))\n"
	enc, err := json.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	res, err := run.py3("-c", run.dir, script, string(enc))
	if err != nil || res.Exit != 0 {
		t.Fatalf("exit %d, err %v, stderr %q", res.Exit, err, res.Stderr)
	}
	var py map[string][2]any
	if err := json.Unmarshal([]byte(res.Stdout), &py); err != nil {
		t.Fatalf("output %q: %v", res.Stdout, err)
	}
	for _, n := range names {
		want := secassess.CredentialHeaderName(n)
		isCred, _ := py[n][0].(bool)
		stored, _ := py[n][1].(string)
		if isCred != want {
			t.Errorf("%s: probe.py says credential=%v, Go says %v", n, isCred, want)
		}
		switch low := strings.ToLower(n); {
		case !want && stored != "plainvalue123":
			t.Errorf("%s: probe.py stored %q for a header that is not a credential", n, stored)
		case want && strings.Contains(stored, "plainvalue123"):
			t.Errorf("%s: probe.py stored %q for a credential header", n, stored)
		case want && low != "cookie" && low != "set-cookie" && low != "authorization" && low != "proxy-authorization" && stored != "[REDACTED]":
			t.Errorf("%s: probe.py stored %q, want [REDACTED]", n, stored)
		}
	}
}

// ---- (6) pace ---------------------------------------------------------------

func TestProbeHelperPace(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{pace: 5})
	// One python process makes the three calls, so only the helper's own wait
	// can space them (separate processes take longer than 200 ms to start).
	script := "from probe import request\nfor _ in range(3):\n    request('GET', '/ok')\n"
	path := filepath.Join(run.dir, "three.py")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if out, err := run.py3(path, run.dir); err != nil || out.Exit != 0 {
		t.Fatalf("exit %d, err %v, stderr %q", out.Exit, err, out.Stderr)
	}
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond || elapsed > 20*time.Second { // the upper bound only catches a hang: a loaded Windows box starts Python slowly
		t.Errorf("three requests at 5 per second took %v", elapsed)
	}
	recs := run.log()
	if len(recs) != 3 {
		t.Fatalf("%d log lines, want 3", len(recs))
	}
	for i := 1; i < len(recs); i++ {
		a, errA := time.Parse(probeHelperTSLayout, recs[i-1].TS)
		b, errB := time.Parse(probeHelperTSLayout, recs[i].TS)
		if errA != nil || errB != nil {
			t.Fatalf("ts %q, %q", recs[i-1].TS, recs[i].TS)
		}
		if gap := b.Sub(a); gap < 150*time.Millisecond {
			t.Errorf("gap between p%d and p%d = %v, want at least 150ms", i, i+1, gap)
		}
	}
	// A refusal is not paced, and a later request waits from the refusal's time only.
	if out := run.probe("GET", "//evil.example/x"); out.Exit != 3 {
		t.Errorf("exit %d", out.Exit)
	}
}

// ---- (7) budget -------------------------------------------------------------

func TestProbeHelperBudget(t *testing.T) {
	t.Parallel()
	budget := func(n int) probeHelperOpts { return probeHelperOpts{cfg: func(c map[string]any) { c["budget"] = n }} }
	t.Run("every refusal past the budget is logged", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, budget(2))
		for i := 0; i < 2; i++ {
			if out := run.probe("GET", "/ok"); out.Exit != 0 {
				t.Fatalf("exit %d: %s", out.Exit, out.Stderr)
			}
		}
		out := run.probe("GET", "/ok")
		probeHelperWantRefused(t, out, run.last(), "budget")
		if n := len(run.log()); n != 3 {
			t.Fatalf("%d lines after the first budget refusal, want 3", n)
		}
		out = run.probe("GET", "/ok")
		probeHelperWantRefused(t, out, run.last(), "budget")
		if n := len(run.log()); n != 4 {
			t.Errorf("%d lines after the second budget refusal, want 4 (a refusal is always logged)", n)
		}
		out = run.probe("GET", "//evil.example/x")
		probeHelperWantRefused(t, out, run.last(), "bad_path")
		out = run.probe("GET", "/ok")
		probeHelperWantRefused(t, out, run.last(), "budget")
		if n := len(run.log()); n != 6 {
			t.Errorf("%d lines, want 6", n)
		}
		if run.srv.count() != 2 {
			t.Errorf("server saw %d requests, want 2", run.srv.count())
		}
	})
	t.Run("a redirect hop costs one", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, budget(2))
		if out := run.probe("GET", "/redir", "--follow"); out.Exit != 0 {
			t.Fatalf("exit %d: %s", out.Exit, out.Stderr)
		}
		if rec := run.last(); rec.Cost != 2 || rec.Hops != 1 {
			t.Errorf("record = %+v", rec)
		}
		probeHelperWantRefused(t, run.probe("GET", "/ok"), run.last(), "budget")
	})
	t.Run("the budget stops a hop", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, budget(1))
		out := run.probe("GET", "/redir", "--follow")
		rec := run.last()
		if out.Exit != 0 || rec.Status != 302 || rec.Hops != 0 || rec.Cost != 1 || rec.RedirectTo != "/ok" || rec.RedirectBlocked {
			t.Errorf("exit %d, record %+v", out.Exit, rec)
		}
		if run.srv.count() != 1 {
			t.Errorf("server saw %d requests, want 1", run.srv.count())
		}
	})
}

// ---- (8) connection errors and timeouts -------------------------------------

func TestProbeHelperConnectionError(t *testing.T) {
	t.Parallel()
	t.Run("closed port", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, probeHelperOpts{origin: probeHelperClosedOrigin(t)})
		out := run.probe("GET", "/ok")
		rec := run.last()
		if out.Exit != 1 || !strings.Contains(out.Stderr, "no response") || out.Stdout != "" {
			t.Errorf("exit %d, stdout %q, stderr %q", out.Exit, out.Stdout, out.Stderr)
		}
		if !rec.Sent || rec.Status != 0 || rec.Error == "" || len(rec.Error) > 200 || rec.Cost != 1 || rec.Refused != "" || rec.Method != "GET" {
			t.Errorf("record = %+v", rec)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		run := newProbeHelperRun(t, probeHelperOpts{})
		start := time.Now()
		out := run.probe("GET", "/slow", "--timeout", "1")
		rec := run.last()
		if out.Exit != 1 || !rec.Sent || rec.Status != 0 || rec.Error == "" || rec.Cost != 1 {
			t.Errorf("exit %d, record %+v", out.Exit, rec)
		}
		if elapsed := time.Since(start); elapsed < 900*time.Millisecond || rec.MS < 900 {
			t.Errorf("elapsed %v, ms %d, want the one second timeout to apply", elapsed, rec.MS)
		}
		if run.srv.count() != 1 {
			t.Errorf("server saw %d requests", run.srv.count())
		}
	})
}

// ---- (9) lockout ------------------------------------------------------------

func TestProbeHelperLockout(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	for i := 0; i < 10; i++ {
		out := run.probe("POST", fmt.Sprintf("/login?u=%d", i), "--account", "alice", "-d", "pw")
		if out.Exit != 0 {
			t.Fatalf("attempt %d: exit %d: %s", i+1, out.Exit, out.Stderr)
		}
	}
	probeHelperWantRefused(t, run.probe("POST", "/login?u=11", "--account", "alice", "-d", "pw"), run.last(), "lockout")
	if run.srv.count() != 10 {
		t.Fatalf("server saw %d requests, want 10", run.srv.count())
	}
	rows := []struct {
		name string
		args []string
		exit int
	}{
		{"another account on the same path", []string{"POST", "/login", "--account", "bob"}, 0},
		{"the same account on another path", []string{"POST", "/other", "--account", "alice"}, 0},
		{"no account is not counted", []string{"POST", "/login"}, 0},
		{"the same account and path is still locked", []string{"POST", "/login", "--account", "alice"}, 3},
		// The same path under another spelling is the same path to most servers.
		{"another method", []string{"GET", "/login", "--account", "alice"}, 3},
		{"another method, put", []string{"PUT", "/login", "--account", "alice"}, 3},
		{"letter case", []string{"POST", "/Login", "--account", "alice"}, 3},
		{"a trailing slash", []string{"POST", "/login/", "--account", "alice"}, 3},
		{"a dot segment", []string{"POST", "/./login", "--account", "alice"}, 3},
		{"a parent segment", []string{"POST", "/a/../login", "--account", "alice"}, 3},
		{"a path parameter", []string{"POST", "/login;x=1", "--account", "alice"}, 3},
		{"a percent-encoded letter", []string{"POST", "/%6cogin", "--account", "alice"}, 3},
		{"a repeated slash", []string{"POST", "/login//", "--account", "alice"}, 3},
		{"a query string", []string{"POST", "/login?next=%2F", "--account", "alice"}, 3},
		{"an encoded slash is another path", []string{"POST", "/login%2Fx", "--account", "alice"}, 0},
		{"a longer path is another path", []string{"POST", "/login/x", "--account", "alice"}, 0},
		{"another label is another account", []string{"POST", "/login", "--account", "alice2"}, 0},
	}
	want := 10 // the ten attempts above
	for _, row := range rows {
		out := run.probe(row.args...)
		if out.Exit != row.exit {
			t.Errorf("%s: exit %d, want %d (%s)", row.name, out.Exit, row.exit, out.Stderr)
		}
		if row.exit == 0 {
			want++
		}
	}
	if run.srv.count() != want {
		t.Errorf("server saw %d requests, want %d", run.srv.count(), want)
	}
}

func TestProbeHelperLockPath(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	script := "import json, sys\nsys.path.insert(0, '.')\nimport probe\nprint(json.dumps([probe._lock_path(p) for p in json.loads(sys.argv[1])]))\n"
	in := []string{"/login", "/Login", "/login/", "/", "/./login", "/a/../login", "/../login", "/login;x=1", "/%6cogin", "/%2e%2e/login", "/login%2fx", "/login%2Fx", "/a//b", "/login?x=1"}
	want := []string{"/login", "/login", "/login", "/", "/login", "/login", "/login", "/login", "/login", "/login", "/login%2fx", "/login%2fx", "/a/b", "/login"}
	enc, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	res, err := run.py3("-c", run.dir, script, string(enc))
	if err != nil || res.Exit != 0 {
		t.Fatalf("exit %d, err %v, stderr %q", res.Exit, err, res.Stderr)
	}
	var got []string
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("output %q: %v", res.Stdout, err)
	}
	for i := range in {
		if i >= len(got) || got[i] != want[i] {
			t.Errorf("_lock_path(%q) = %q, want %q", in[i], got[i], want[i])
		}
	}
}

// ---- (10) redirects ---------------------------------------------------------

func TestProbeHelperRedirects(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name     string
		args     []string
		status   int
		hops     int
		cost     int
		to       string
		blocked  bool
		requests int
		extra    func(t *testing.T, run *probeHelperRun, out probeHelperOut)
	}{
		{"not followed by default", []string{"GET", "/redir"}, 302, 0, 1, "/ok", false, 1, func(t *testing.T, run *probeHelperRun, out probeHelperOut) {
			if !strings.Contains(out.Stdout, "\nLocation: /ok\n") {
				t.Errorf("stdout = %q", out.Stdout)
			}
		}},
		{"same origin followed", []string{"GET", "/redir", "--follow"}, 200, 1, 2, "", false, 2, func(t *testing.T, run *probeHelperRun, out probeHelperOut) {
			if !strings.HasSuffix(out.Stdout, "\n\nhello") || run.last().Path != "/redir" {
				t.Errorf("stdout = %q, path %q", out.Stdout, run.last().Path)
			}
		}},
		{"other origin not followed", []string{"GET", "/redir-ext", "--follow"}, 302, 0, 1, "http://evil.example/x", true, 1, nil},
		{"scheme-relative location not followed", []string{"GET", "/redir-sr", "--follow"}, 302, 0, 1, "//evil.example/x", true, 1, nil},
		{"other origin without follow", []string{"GET", "/redir-ext"}, 302, 0, 1, "http://evil.example/x", false, 1, nil},
		{"hop limit is three", []string{"GET", "/loop", "--follow"}, 302, 3, 4, "/loop", false, 4, nil},
		{"303 becomes a GET without the body", []string{"POST", "/see-other", "-H", "Content-Type: text/plain", "-d", "a=1", "--follow"}, 200, 1, 2, "", false, 2, func(t *testing.T, run *probeHelperRun, out probeHelperOut) {
			first, second := run.srv.at(0), run.srv.at(1)
			if first.Method != "POST" || first.Body != "a=1" || second.Method != "GET" || second.Body != "" || second.Header.Get("Content-Type") != "" {
				t.Errorf("server saw %+v then %+v", first, second)
			}
		}},
		{"307 keeps the method and body", []string{"POST", "/temp", "-d", "a=1", "--follow"}, 200, 1, 2, "", false, 2, func(t *testing.T, run *probeHelperRun, out probeHelperOut) {
			if second := run.srv.at(1); second.Method != "POST" || second.Body != "a=1" {
				t.Errorf("server saw %+v", second)
			}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			run := newProbeHelperRun(t, probeHelperOpts{})
			out := run.probe(row.args...)
			rec := run.last()
			if out.Exit != 0 || rec.Status != row.status || rec.Hops != row.hops || rec.Cost != row.cost || rec.RedirectTo != row.to || rec.RedirectBlocked != row.blocked || !rec.Sent {
				t.Errorf("exit %d, record %+v", out.Exit, rec)
			}
			if n := run.srv.count(); n != row.requests {
				t.Errorf("server saw %d requests, want %d", n, row.requests)
			}
			if row.extra != nil {
				row.extra(t, run, out)
			}
		})
	}
}

// TestProbeHelperRedirectPace: a followed hop waits the pace like a request, so
// "N requests per second" holds for the requests the target sees.
func TestProbeHelperRedirectPace(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{pace: 4})
	out := run.probe("GET", "/loop", "--follow")
	rec := run.last()
	if out.Exit != 0 || rec.Hops != 3 || rec.Cost != 4 || run.srv.count() != 4 {
		t.Fatalf("exit %d, record %+v, server saw %d", out.Exit, rec, run.srv.count())
	}
	// Four requests at 4 per second: three waits of 250 ms between them.
	if rec.MS < 700 {
		t.Errorf("four requests at 4 per second took %d ms, want at least 700", rec.MS)
	}
}

// TestProbeHelperLogFull: past 12 MiB the helper stops sending (and cannot log
// the refusal), so the log never grows beyond what Observer reads back.
func TestProbeHelperLogFull(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	path := filepath.Join(run.dir, "probes.jsonl")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'\n'}, 12<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	out := run.probe("GET", "/ok")
	if out.Exit != 3 || !strings.Contains(out.Stderr, "(log_full)") || run.srv.count() != 0 {
		t.Fatalf("exit %d, stderr %q, server saw %d", out.Exit, out.Stderr, run.srv.count())
	}
	if st, err := os.Stat(path); err != nil || st.Size() != 12<<20 {
		t.Errorf("log after the refusal: %v, %v, want it unchanged", st, err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'\n'}, 12<<20-1), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := run.probe("GET", "/ok"); out.Exit != 0 || run.srv.count() != 1 {
		t.Errorf("just under the stop: exit %d, server saw %d", out.Exit, run.srv.count())
	}
}

// TestProbeHelperAcceptsEveryTargetSpelling: every loopback spelling
// secassess.ParseTarget accepts becomes an origin the helper accepts, so a
// target the plan calls fine is never one the helper then refuses everything
// under. A spelling of the same address is the same destination: a request
// to the origin as written or to its canonical form is sent to one place.
func TestProbeHelperAcceptsEveryTargetSpelling(t *testing.T) {
	t.Parallel()
	spellings := []string{
		"http://localhost:3000/", "http://LOCALHOST:3000", "http://127.0.0.1:3000", "http://127.8.9.10:80", "https://[::1]:8443",
		"http://[0:0:0:0:0:0:0:1]:5173", "http://[0000:0000:0000:0000:0000:0000:0000:0001]:3000", "http://[::ffff:127.0.0.1]:3000",
		"http://[::ffff:7f00:1]:3000", "http://[::FFFF:127.0.0.1]:3000",
	}
	var origins []string
	for _, raw := range spellings {
		target, err := secassess.ParseTarget(raw)
		if err != nil {
			t.Fatalf("%s: ParseTarget: %v", raw, err)
		}
		origins = append(origins, target.Origin())
	}
	run := newProbeHelperRun(t, probeHelperOpts{})
	script := "import json, sys\nsys.path.insert(0, '.')\nimport probe\nprint(json.dumps([probe._origin_parts(o) for o in json.loads(sys.argv[1])]))\n"
	enc, err := json.Marshal(origins)
	if err != nil {
		t.Fatal(err)
	}
	res, err := run.py3("-c", run.dir, script, string(enc))
	if err != nil || res.Exit != 0 {
		t.Fatalf("exit %d, err %v, stderr %q", res.Exit, err, res.Stderr)
	}
	var got []any
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil || len(got) != len(origins) {
		t.Fatalf("output %q: %v", res.Stdout, err)
	}
	for i, o := range origins {
		if got[i] == nil {
			t.Errorf("the helper refuses the origin %s that ParseTarget gave for %s", o, spellings[i])
		}
	}
	t.Run("a request goes to the same place under another spelling", func(t *testing.T) {
		port := strings.TrimPrefix(run.srv.URL, "http://127.0.0.1:")
		r := newProbeHelperRun(t, probeHelperOpts{origin: "http://[::ffff:127.0.0.1]:" + port})
		if out := r.probe("GET", "/ok"); out.Exit != 0 || r.last().Status != 200 {
			t.Fatalf("exit %d, record %+v, stderr %q", out.Exit, r.last(), out.Stderr)
		}
		// The same address in its canonical spelling is not another host.
		if out := r.probe("GET", run.srv.URL+"/ok"); out.Exit != 0 {
			t.Errorf("an absolute URL on the canonical spelling: exit %d, stderr %q", out.Exit, out.Stderr)
		}
		probeHelperWantRefused(t, r.probe("GET", "http://[::ffff:127.0.0.2]:"+port+"/ok"), r.last(), "off_target")
		if run.srv.count() != 2 {
			t.Errorf("the target saw %d requests, want 2", run.srv.count())
		}
	})
}

// ---- (11) probe.json checks -------------------------------------------------

func TestProbeHelperBadConfig(t *testing.T) {
	t.Parallel()
	raw := func(s string) *string { return &s }
	rows := []struct {
		name string
		opts probeHelperOpts
	}{
		{"origin is not loopback", probeHelperOpts{origin: "http://example.com:3000"}},
		{"origin is a private address", probeHelperOpts{origin: "http://192.168.1.5:3000"}},
		{"origin is another ipv6 address", probeHelperOpts{origin: "http://[::2]:3000"}},
		{"origin has no port", probeHelperOpts{origin: "http://127.0.0.1"}},
		{"origin has a trailing slash", probeHelperOpts{origin: "http://127.0.0.1:3000/"}},
		{"origin has a path", probeHelperOpts{origin: "http://127.0.0.1:3000/x"}},
		{"origin has userinfo", probeHelperOpts{origin: "http://user@127.0.0.1:3000"}},
		{"origin is not http", probeHelperOpts{origin: "ftp://127.0.0.1:21"}},
		{"origin has an invalid octet", probeHelperOpts{origin: "http://127.0.0.256:80"}},
		{"origin is empty", probeHelperOpts{cfg: func(c map[string]any) { c["origin"] = "" }}},
		{"origin is not a string", probeHelperOpts{cfg: func(c map[string]any) { c["origin"] = 123 }}},
		{"schema is wrong", probeHelperOpts{cfg: func(c map[string]any) { c["schema"] = "observer.probe.v2" }}},
		{"schema is missing", probeHelperOpts{cfg: func(c map[string]any) { delete(c, "schema") }}},
		{"run id differs from the config", probeHelperOpts{cfg: func(c map[string]any) { c["run_id"] = "fedcba9876543210" }}},
		{"folder name differs from the run id", probeHelperOpts{dirName: "fedcba9876543210"}},
		{"budget is zero", probeHelperOpts{cfg: func(c map[string]any) { c["budget"] = 0 }}},
		{"budget is negative", probeHelperOpts{cfg: func(c map[string]any) { c["budget"] = -1 }}},
		{"budget is a string", probeHelperOpts{cfg: func(c map[string]any) { c["budget"] = "5" }}},
		{"budget is a boolean", probeHelperOpts{cfg: func(c map[string]any) { c["budget"] = true }}},
		{"budget is a fraction", probeHelperOpts{cfg: func(c map[string]any) { c["budget"] = 1.5 }}},
		{"pace is zero", probeHelperOpts{cfg: func(c map[string]any) { c["pace_rps"] = 0 }}},
		{"max_bytes is zero", probeHelperOpts{cfg: func(c map[string]any) { c["max_bytes"] = 0 }}},
		{"max_bytes is missing", probeHelperOpts{cfg: func(c map[string]any) { delete(c, "max_bytes") }}},
		{"not json", probeHelperOpts{raw: raw("not json")}},
		{"not an object", probeHelperOpts{raw: raw("[]")}},
		{"no probe.json", probeHelperOpts{noFile: true}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			run := newProbeHelperRun(t, row.opts)
			out := run.probe("GET", "/ok")
			probeHelperWantRefused(t, out, run.last(), "bad_config")
			if run.srv.count() != 0 {
				t.Errorf("server saw %d requests", run.srv.count())
			}
			if len(run.log()) != 1 {
				t.Errorf("%d log lines, want the refusal", len(run.log()))
			}
		})
	}
	t.Run("localhost is a loopback origin", func(t *testing.T) {
		t.Parallel()
		target := newProbeHelperServer(t)
		_, port, _ := strings.Cut(probeHelperHost(target), ":")
		run := newProbeHelperRun(t, probeHelperOpts{origin: "http://localhost:" + port})
		out := run.probe("GET", "/ok")
		if out.Exit != 0 || target.count() != 1 {
			t.Errorf("exit %d, stderr %q, target saw %d requests: a localhost origin is allowed", out.Exit, out.Stderr, target.count())
		}
	})
}

// ---- (12) the python API ----------------------------------------------------

func TestProbeHelperPythonAPI(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	script := `from probe import request, ProbeRefused
r = request("GET", "/ok", headers={"X-Test": "py"}, role="attack", wstg="INFO", note="api")
print(r["id"], r["status"], r["body"], r["record"]["cost"], r["record"]["role"], len(r["headers"]) > 0)
try:
    request("GET", "http://evil.example/x")
except ProbeRefused as e:
    print("refused", e.code)
try:
    request("GET", "/ok", role="bogus")
except ValueError:
    print("valueerror")
r = request("POST", "/echo", headers=[("X-A", "1"), "X-B: 2"], body=b"abc")
print(r["id"], r["status"], r["body"])
`
	path := filepath.Join(run.dir, "try_probe.py")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run.py3(path, t.TempDir()) // run from a different working directory
	if err != nil || out.Exit != 0 {
		t.Fatalf("exit %d, err %v, stderr %q", out.Exit, err, out.Stderr)
	}
	want := "p1 200 hello 1 attack True\nrefused off_target\nvalueerror\np3 200 echo POST abc\n"
	if strings.ReplaceAll(out.Stdout, "\r\n", "\n") != want {
		t.Errorf("stdout = %q, want %q", out.Stdout, want)
	}
	recs := run.log()
	if len(recs) != 3 || !recs[0].Sent || recs[1].Refused != "off_target" || recs[1].Sent || recs[2].ID != "p3" {
		t.Errorf("log = %+v, want p1 sent, p2 refused, p3 sent and nothing for the value error", recs)
	}
	if run.srv.count() != 2 || run.srv.at(0).Header.Get("X-Test") != "py" || run.srv.at(1).Header.Get("X-B") != "2" {
		t.Errorf("server saw %d requests: %+v", run.srv.count(), run.srv.at(1))
	}

	closed := newProbeHelperRun(t, probeHelperOpts{origin: probeHelperClosedOrigin(t)})
	path = filepath.Join(closed.dir, "try_probe.py")
	script = "from probe import request\nr = request('GET', '/')\nprint(r['status'], r['record']['sent'], bool(r['record']['error']), r['body'] == '')\n"
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = closed.py3(path, closed.dir)
	if err != nil || out.Exit != 0 || strings.TrimSpace(out.Stdout) != "0 True True True" {
		t.Errorf("connection error through the API: exit %d, err %v, stdout %q, stderr %q", out.Exit, err, out.Stdout, out.Stderr)
	}
}

// ---- (13) concurrency -------------------------------------------------------

func TestProbeHelperConcurrency(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	const n = 8
	outs := make([]probeHelperOut, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outs[i], errs[i] = run.py3(filepath.Join(run.dir, "probe.py"), run.dir, "GET", fmt.Sprintf("/delay?i=%d", i))
		}(i)
	}
	wg.Wait()
	for i := range outs {
		if errs[i] != nil || outs[i].Exit != 0 {
			t.Errorf("invocation %d: exit %d, err %v, stderr %q", i, outs[i].Exit, errs[i], outs[i].Stderr)
		}
	}
	recs := run.log()
	if len(recs) != n {
		t.Fatalf("%d log lines, want %d", len(recs), n)
	}
	paths := map[string]bool{}
	for i, rec := range recs {
		if rec.ID != fmt.Sprintf("p%d", i+1) || !rec.Sent {
			t.Errorf("line %d = %+v", i+1, rec)
		}
		paths[rec.Path] = true
	}
	if len(paths) != n || run.srv.count() != n {
		t.Errorf("%d distinct paths, server saw %d requests, want %d each", len(paths), run.srv.count(), n)
	}
}

// ---- (14) the file itself ---------------------------------------------------

func TestProbeHelperSource(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("probe")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "probe.py" || entries[0].IsDir() {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("probe/ holds %v, want only probe.py", names)
	}
	src := probeHelperSource(t)
	if bytes.IndexByte(src, '\r') >= 0 || !bytes.HasSuffix(src, []byte("\n")) {
		t.Errorf("probe.py must use LF endings and end with a newline")
	}
	for i, line := range strings.Split(string(src), "\n") {
		if strings.TrimRight(line, " \t") != line {
			t.Errorf("line %d has trailing whitespace", i+1)
		}
	}
	run := newProbeHelperRun(t, probeHelperOpts{})
	scan := `import ast, json, sys
with open(sys.argv[1], "rb") as f:
    tree = ast.parse(f.read())
names = lambda n: [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module]
every = sorted({m for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for m in names(n)})
top = sorted({m for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) for m in names(n)})
print(json.dumps({"every": every, "top": top}))
`
	scanned, err := run.py3("-c", run.dir, scan, filepath.Join(run.dir, "probe.py"))
	if err != nil || scanned.Exit != 0 {
		t.Fatalf("import scan: exit %d, err %v, stderr %q", scanned.Exit, err, scanned.Stderr)
	}
	raw := scanned.Stdout
	var got struct{ Every, Top []string }
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("import scan output %q: %v", raw, err)
	}
	allowed := map[string]bool{}
	for _, m := range strings.Fields("argparse base64 datetime errno fcntl hashlib http.client ipaddress json msvcrt os re ssl sys time urllib.parse") {
		allowed[m] = true
	}
	for _, m := range got.Every {
		if !allowed[m] {
			t.Errorf("probe.py imports %q, which is not on the allow-list", m)
		}
	}
	for _, m := range got.Top {
		if m == "fcntl" || m == "msvcrt" {
			t.Errorf("%s must be imported inside try/except", m)
		}
	}
	for _, want := range []string{"fcntl", "msvcrt"} {
		found := false
		for _, m := range got.Every {
			found = found || m == want
		}
		if !found {
			t.Errorf("probe.py does not import %s (the lock must work on Linux and Windows)", want)
		}
	}
	// Importing the module raises no warning of any kind.
	imp, err := run.py3("-W", run.dir, "error", "-c", "import probe")
	if err != nil || imp.Exit != 0 {
		t.Errorf("import probe under -W error: exit %d, err %v, stderr %q", imp.Exit, err, imp.Stderr)
	}
}

// ---- (15) help and usage errors ---------------------------------------------

func TestProbeHelperHelp(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	out := run.probe("--help")
	if out.Exit != 0 || !strings.Contains(out.Stdout, "probes.jsonl") {
		t.Errorf("--help: exit %d, stdout %q", out.Exit, out.Stdout)
	}
	// The usage text carries the rule about a hidden value, since the prompt has no room for it.
	if flat := strings.Join(strings.Fields(out.Stdout), " "); !strings.Contains(flat, "[REDACTED] in place of a credential value: in indicator.when name the field and [REDACTED], never the value") {
		t.Errorf("--help does not say how to name a hidden value: %q", out.Stdout)
	}
	for _, args := range [][]string{
		nil,
		{"GET"},
		{"GET", "/ok", "--role", "bogus"},
		{"GET", "/ok", "--wstg", "XXXX"},
		{"GET", "/ok", "--account", "has space"},
		{"GET", "/ok", "--account", strings.Repeat("a", 41)},
		{"GET", "/ok", "--timeout", "soon"},
		{"GET", "/ok", "--unknown"},
	} {
		if out := run.probe(args...); out.Exit != 2 {
			t.Errorf("%v: exit %d, want 2", args, out.Exit)
		}
	}
	if n := len(run.log()); n != 0 || run.srv.count() != 0 {
		t.Errorf("usage errors left %d log lines and %d requests", n, run.srv.count())
	}
}

// ---- extra: https origin, record size ---------------------------------------

func TestProbeHelperHTTPS(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{tls: true})
	if !strings.HasPrefix(run.srv.URL, "https://") {
		t.Fatalf("target = %q", run.srv.URL)
	}
	out := run.probe("GET", "/ok")
	rec := run.last()
	if out.Exit != 0 || rec.Status != 200 || rec.BodyExcerpt != "hello" || !rec.Sent {
		t.Errorf("a self-signed loopback origin: exit %d, stderr %q, record %+v", out.Exit, out.Stderr, rec)
	}
	out = run.probe("GET", run.srv.URL+"/ok?x=1")
	if out.Exit != 0 || run.last().Path != "/ok?x=1" {
		t.Errorf("absolute https url: exit %d, record %+v", out.Exit, run.last())
	}
	out = run.probe("GET", "http://"+strings.TrimPrefix(run.srv.URL, "https://")+"/ok")
	probeHelperWantRefused(t, out, run.last(), "off_target")
	if run.srv.count() != 2 {
		t.Errorf("server saw %d requests, want 2", run.srv.count())
	}
}

func TestProbeHelperRecordSize(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	out := run.probe("GET", "/wide", "-H", "X-Note: "+strings.Repeat("\u00e9", 500), "--note", strings.Repeat("\u00e9", 500))
	if out.Exit != 0 {
		t.Fatalf("exit %d: %s", out.Exit, out.Stderr)
	}
	rec := run.last()
	line := strings.TrimSuffix(run.rawLog(), "\n")
	if len(line) > 24576 {
		t.Errorf("record is %d bytes, want at most 24576", len(line))
	}
	if rec.Status != 200 || rec.BodyBytes != 65536 || !rec.BodyTruncated || utf8.RuneCountInString(rec.Note) != 200 {
		t.Errorf("record = status %d, body_bytes %d, truncated %v, note %d characters", rec.Status, rec.BodyBytes, rec.BodyTruncated, utf8.RuneCountInString(rec.Note))
	}
	if len(out.Stdout) < 65536 || !strings.Contains(out.Stdout, "X-Wide-44: ") {
		t.Errorf("stdout must still show every header and the capped body (%d bytes)", len(out.Stdout))
	}
}

func TestProbeHelperDamagedLog(t *testing.T) {
	t.Parallel()
	run := newProbeHelperRun(t, probeHelperOpts{})
	// What the agent could leave behind: text, a line too deep to parse, a
	// record with odd types, and no newline at the end.
	before := "not json\n" + strings.Repeat("[", 200000) + "\n" + `{"sent":true,"cost":"x","ts":5}`
	if err := os.WriteFile(filepath.Join(run.dir, "probes.jsonl"), []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	out := run.probe("GET", "/ok", "--account", "alice")
	if out.Exit != 0 {
		t.Fatalf("exit %d: %s", out.Exit, out.Stderr)
	}
	raw := run.rawLog()
	if !strings.HasPrefix(raw, before+"\n") {
		t.Fatalf("existing lines were changed")
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	var rec probeHelperRec
	if len(lines) != 4 || json.Unmarshal([]byte(lines[3]), &rec) != nil || rec.ID != "p4" || !rec.Sent || rec.Status != 200 {
		t.Errorf("%d lines, last %q; want a fourth line with id p4", len(lines), lines[len(lines)-1])
	}
}
