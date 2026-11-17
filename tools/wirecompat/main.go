package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// maxPushes bounds the push loop per mode. The fixture fits one batch; a
// version that needs more than this is a recorder bug, not a bigger fixture.
const maxPushes = 8

// pushPath is the agent push route (openapi PushBatch). The fake org
// records only bodies posted here.
const pushPath = "/api/agent/push"

// metaFile is the per-version manifest the replay test reads.
const metaFile = "meta.json"

// shareMode is one [org_client.share] posture whose wire shape differs from
// the others. The table is walked in order; each row records its own files.
type shareMode struct {
	// name is the file prefix and the mode's name in meta.json.
	name string
	// share is the node's [org_client.share] block for this mode.
	share config.OrgClientShareConfig
}

// shareModes are the wire shapes a node ships: hashes only (the zero
// value, an individual node that has not opted in) and full content (a
// managed node, or an individual node that set full_content). admin_managed
// ships the same columns as full_content (ShareOptions.shipsRawContent), so
// it adds no shape of its own.
var shareModes = []shareMode{
	{name: "metadata-only", share: config.OrgClientShareConfig{}},
	{name: "full-content", share: config.OrgClientShareConfig{FullContent: true}},
}

// Meta is meta.json: what the replay test needs to place a recording in the
// D-30 support window and check it.
type Meta struct {
	// Version is the release tag (v1.31.0) or "main" for an unreleased tree.
	Version string `json:"version"`
	// AgentVersion is the agent_version the envelopes carry.
	AgentVersion string `json:"agent_version"`
	// Released is the tag's date (YYYY-MM-DD, UTC); for "main", the commit's.
	Released string `json:"released"`
	// Unreleased marks a recording of a tree that is not a release tag.
	Unreleased bool `json:"unreleased,omitempty"`
	// Commit is the recorded tree's commit sha, when known.
	Commit string `json:"commit,omitempty"`
	// Recorder names the program that wrote the files.
	Recorder string `json:"recorder"`
	// Modes lists each share mode and its push files, in push order.
	Modes []MetaMode `json:"modes"`
}

// MetaMode is one share mode's recording.
type MetaMode struct {
	// Name is the shareMode name.
	Name string `json:"name"`
	// Pushes are the envelope file names, in the order they were pushed.
	Pushes []string `json:"pushes"`
}

// options are the parsed flags.
type options struct {
	out          string
	version      string
	agentVersion string
	released     string
	commit       string
	forbid       []string
}

// forbidList is a repeatable -forbid flag.
type forbidList []string

// String implements flag.Value.
func (f *forbidList) String() string { return strings.Join(*f, ",") }

// Set implements flag.Value.
func (f *forbidList) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	opts, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "wirecompat:", err)
		os.Exit(1)
	}
	if err := run(context.Background(), opts); err != nil {
		fmt.Fprintln(os.Stderr, "wirecompat:", err)
		os.Exit(1)
	}
}

var (
	versionRe  = regexp.MustCompile(`^(main|v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)$`)
	releasedRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// parseFlags parses and validates the command line.
func parseFlags(args []string) (options, error) {
	var o options
	var forbid forbidList
	fs := flag.NewFlagSet("wirecompat", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.out, "out", "", "output directory (testdata/wirecompat/<version>)")
	fs.StringVar(&o.version, "version", "", "release tag (v1.31.0) or main")
	fs.StringVar(&o.agentVersion, "agent-version", "", "agent_version the node reports (default: -version without the v)")
	fs.StringVar(&o.released, "released", "", "release date, YYYY-MM-DD")
	fs.StringVar(&o.commit, "commit", "", "commit sha of the recorded tree")
	fs.Var(&forbid, "forbid", "a string no envelope may contain (repeatable)")
	if err := fs.Parse(args); err != nil {
		return options{}, fmt.Errorf("parseFlags: %w", err)
	}
	if fs.NArg() != 0 {
		return options{}, fmt.Errorf("parseFlags: unexpected argument %q", fs.Arg(0))
	}
	if o.out == "" {
		return options{}, errors.New("parseFlags: -out is required")
	}
	if !versionRe.MatchString(o.version) {
		return options{}, fmt.Errorf("parseFlags: -version %q must be main or v<major>.<minor>.<patch>", o.version)
	}
	if !releasedRe.MatchString(o.released) {
		return options{}, fmt.Errorf("parseFlags: -released %q must be YYYY-MM-DD", o.released)
	}
	if _, err := time.Parse("2006-01-02", o.released); err != nil {
		return options{}, fmt.Errorf("parseFlags: -released: %w", err)
	}
	if o.agentVersion == "" {
		o.agentVersion = strings.TrimPrefix(o.version, "v")
	}
	for _, f := range forbid {
		if f = strings.TrimSpace(f); len(f) >= 3 {
			o.forbid = append(o.forbid, f)
		}
	}
	return o, nil
}

// run records every share mode, checks every envelope, then writes the
// directory. Nothing is written unless every mode succeeded.
func run(ctx context.Context, o options) error {
	files := map[string][]byte{}
	meta := Meta{
		Version: o.version, AgentVersion: o.agentVersion, Released: o.released,
		Unreleased: o.version == "main", Commit: o.commit, Recorder: "tools/wirecompat",
	}
	for _, m := range shareModes {
		bodies, err := recordMode(ctx, m, o.agentVersion)
		if err != nil {
			return fmt.Errorf("run: mode %s: %w", m.name, err)
		}
		mm := MetaMode{Name: m.name}
		for i, b := range bodies {
			pretty, err := checkEnvelope(b, o.agentVersion, o.forbid)
			if err != nil {
				return fmt.Errorf("run: mode %s push %d: %w", m.name, i+1, err)
			}
			name := fmt.Sprintf("%s.push-%02d.json", m.name, i+1)
			files[name] = pretty
			mm.Pushes = append(mm.Pushes, name)
		}
		meta.Modes = append(meta.Modes, mm)
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("run: meta: %w", err)
	}
	files[metaFile] = append(mb, '\n')
	return writeDir(o.out, files)
}

// writeDir replaces the recorder's own files in dir with files.
func writeDir(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("writeDir: %w", err)
	}
	old, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("writeDir: %w", err)
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("writeDir: %w", err)
		}
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return fmt.Errorf("writeDir: %w", err)
		}
	}
	return nil
}

// envNameMarkers are process-environment names that must never reach a
// fixture (an env listing would carry them).
var envNameMarkers = []string{"USERPROFILE", "LOCALAPPDATA", "APPDATA", "GOPATH", "GOROOT", "XDG_", "PATH="}

// checkEnvelope verifies one decoded push body (a JSON object stamped with
// agentVersion, free of every forbid value and env-name marker) and returns
// it indented.
func checkEnvelope(body []byte, agentVersion string, forbid []string) ([]byte, error) {
	var head struct {
		AgentVersion string `json:"agent_version"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return nil, fmt.Errorf("checkEnvelope: not a JSON envelope: %w", err)
	}
	if head.AgentVersion != agentVersion {
		return nil, fmt.Errorf("checkEnvelope: agent_version %q, want %q", head.AgentVersion, agentVersion)
	}
	lower := strings.ToLower(string(body))
	for i, f := range forbid {
		if strings.Contains(lower, strings.ToLower(f)) {
			return nil, fmt.Errorf("checkEnvelope: contains -forbid value #%d (a host name, user or home path)", i+1)
		}
		// A JSON-escaped Windows path doubles every backslash.
		if esc := strings.ReplaceAll(f, `\`, `\\`); esc != f && strings.Contains(lower, strings.ToLower(esc)) {
			return nil, fmt.Errorf("checkEnvelope: contains -forbid value #%d (escaped)", i+1)
		}
	}
	for _, m := range envNameMarkers {
		if strings.Contains(string(body), m) {
			return nil, fmt.Errorf("checkEnvelope: contains the environment name %q", m)
		}
	}
	var out bytes.Buffer
	if err := json.Indent(&out, body, "", "  "); err != nil {
		return nil, fmt.Errorf("checkEnvelope: indent: %w", err)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// recordMode runs one share mode on a fresh node database and returns the
// decoded push bodies in order.
func recordMode(ctx context.Context, m shareMode, agentVersion string) ([][]byte, error) {
	tmp, err := os.MkdirTemp("", "wirecompat-node-")
	if err != nil {
		return nil, fmt.Errorf("recordMode: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	sqlDB, err := db.Open(ctx, db.Options{Path: filepath.Join(tmp, "observer.db")})
	if err != nil {
		return nil, fmt.Errorf("recordMode: open node db: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()
	st := store.New(sqlDB)

	org := &fakeOrg{}
	srv := httptest.NewServer(org)
	defer srv.Close()

	// Enrol first, the way a real node captures after `observer org enroll`.
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: fixtureOrgID, OrgName: "Wirecompat Example Org", OrgServerURL: srv.URL,
		UserID: fixtureUserID, UserEmail: fixtureUserEmail,
		EnrolledAt: "2026-08-01T08:00:00Z", BearerKeyID: fixturePlaceholder,
	}); err != nil {
		return nil, fmt.Errorf("recordMode: %w", err)
	}
	if err := seed(ctx, st, sqlDB); err != nil {
		return nil, fmt.Errorf("recordMode: %w", err)
	}

	client := orgclient.New(config.OrgClientConfig{
		Enabled: true, OrgServerURL: srv.URL, Share: m.share,
	}, st, newFixtureSecrets(), agentVersion, srv.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	pushes := 0
	for ; pushes < maxPushes; pushes++ {
		res, err := client.PushOnce(ctx)
		if err != nil {
			return nil, fmt.Errorf("recordMode: push %d: %w", pushes+1, err)
		}
		if res.Empty {
			break
		}
	}
	if pushes == maxPushes {
		return nil, fmt.Errorf("recordMode: still not empty after %d pushes", maxPushes)
	}
	bodies, stray := org.recorded()
	if len(stray) > 0 {
		return nil, fmt.Errorf("recordMode: the node made requests other than the push: %s", strings.Join(stray, ", "))
	}
	if len(bodies) != pushes || pushes == 0 {
		return nil, fmt.Errorf("recordMode: %d pushes reported, %d bodies received", pushes, len(bodies))
	}
	return bodies, nil
}

// fakeOrg is the in-process org server: it keeps every decoded push body
// and answers 200 with an empty acknowledgment.
type fakeOrg struct {
	mu     sync.Mutex
	bodies [][]byte
	stray  []string
}

// ServeHTTP implements http.Handler.
func (f *fakeOrg) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != pushPath {
		f.mu.Lock()
		f.stray = append(f.stray, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	body, err := decodeBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var cur struct {
		CursorTo int64 `json:"cursor_to"`
	}
	_ = json.Unmarshal(body, &cur)
	f.mu.Lock()
	f.bodies = append(f.bodies, body)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"accepted_rows":0,"deduped_rows":0,"next_cursor":%d}`, cur.CursorTo)
}

// recorded returns the push bodies and any other request lines.
func (f *fakeOrg) recorded() ([][]byte, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.bodies...), append([]string(nil), f.stray...)
}

// decodeBody returns the request body, inflated when gzip-encoded (the node
// always compresses).
func decodeBody(r *http.Request) ([]byte, error) {
	var rd io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, fmt.Errorf("decodeBody: %w", err)
		}
		defer func() { _ = zr.Close() }()
		rd = zr
	}
	b, err := io.ReadAll(io.LimitReader(rd, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("decodeBody: %w", err)
	}
	return b, nil
}
