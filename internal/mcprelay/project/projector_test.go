package project

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// disk is the shared in-memory file system the fake writer and the fake
// journal both see (nil entry = absent file).
type disk struct {
	files map[string][]byte
	log   []string // seam call order
}

func newDisk() *disk { return &disk{files: map[string][]byte{}} }

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeWriter is an in-memory {"mcpServers":{...}} writer: Stage wraps every
// stdio entry that is not observer / not already the wrapper and upserts
// the remote entries; Commit CASes on Before; Revert reverses only the
// relay-owned entries under the same CAS.
type fakeWriter struct {
	d *disk
	// ignoreBind makes the writer wrap every stdio entry regardless of the
	// binding (a buggy writer the projector must refuse).
	ignoreBind bool
	stageErr   error
	commitErr  error
	revertErr  error
	commits    int
	stageCalls int
}

func (w *fakeWriter) load(path string) (map[string]any, map[string]any, bool) {
	before, exists := w.d.files[path]
	doc := map[string]any{}
	if exists {
		_ = json.Unmarshal(before, &doc)
	}
	servers, _ := doc["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	return doc, servers, exists
}

func (w *fakeWriter) Stage(_ context.Context, c Client, desired Desired) (Staged, error) {
	w.stageCalls++
	w.d.log = append(w.d.log, "stage:"+c.Tool)
	if w.stageErr != nil {
		return Staged{}, w.stageErr
	}
	doc, servers, exists := w.load(c.ConfigPath)
	st := Staged{}
	if exists {
		st.Before = w.d.files[c.ConfigPath]
	}
	keys := make([]string, 0, len(servers))
	for k := range servers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if desired.Wrap != nil {
		for _, k := range keys {
			e, _ := servers[k].(map[string]any)
			cmd, _ := e["command"].(string)
			if cmd == "" || e["url"] != nil {
				continue
			}
			var args []string
			for _, a := range asSlice(e["args"]) {
				args = append(args, fmt.Sprint(a))
			}
			if IsObserver(cmd, *desired.Wrap) || IsWrapper(cmd, args, *desired.Wrap) {
				continue
			}
			b, ok := desired.Wrap.BindingFor(k)
			if !ok && !w.ignoreBind {
				continue
			}
			cwd, _ := e["cwd"].(string)
			var envKeys []string
			if env, ok := e["env"].(map[string]any); ok {
				for ek := range env {
					envKeys = append(envKeys, ek)
				}
				sort.Strings(envKeys)
			}
			st.Wrapped = append(st.Wrapped, StdioEntry{Key: k, Command: cmd, Args: args, Cwd: cwd, EnvKeys: envKeys, VServer: b.VServer, ServerID: b.ServerID})
			e["command"] = desired.Wrap.Command
			e["args"] = WrapArgs(c.Tool, k, *desired.Wrap)
			servers[k] = e
		}
	}
	for _, r := range desired.Remote {
		want := map[string]any{"url": r.URL}
		if cur, ok := servers[r.Name].(map[string]any); ok && cur["url"] == r.URL {
			continue
		}
		servers[r.Name] = want
		st.RemoteKeys = append(st.RemoteKeys, r.Name)
	}
	doc["mcpServers"] = servers
	st.After, _ = json.Marshal(doc)
	st.Changed = len(st.Wrapped) > 0 || len(st.RemoteKeys) > 0
	return st, nil
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func (w *fakeWriter) Commit(_ context.Context, c Client, st Staged) error {
	w.d.log = append(w.d.log, "commit:"+c.Tool)
	if w.commitErr != nil {
		return w.commitErr
	}
	cur, exists := w.d.files[c.ConfigPath]
	if (st.Before == nil) != !exists || string(cur) != string(st.Before) {
		return fmt.Errorf("%w: %s", ErrConfigChanged, c.ConfigPath)
	}
	w.commits++
	w.d.files[c.ConfigPath] = st.After
	return nil
}

func (w *fakeWriter) Revert(_ context.Context, c Client, rows []JournalRow) error {
	w.d.log = append(w.d.log, "revert:"+c.Tool)
	if w.revertErr != nil {
		return w.revertErr
	}
	doc, servers, exists := w.load(c.ConfigPath)
	if !exists {
		return nil
	}
	for _, r := range rows {
		switch r.Kind() {
		case RowRemote:
			delete(servers, r.EntryKey)
		case RowStdioWrap:
			e, ok := servers[r.EntryKey].(map[string]any)
			if !ok {
				continue
			}
			e["command"] = r.OrigCommand
			args := make([]any, 0, len(r.OrigArgs))
			for _, a := range r.OrigArgs {
				args = append(args, a)
			}
			e["args"] = args
			servers[r.EntryKey] = e
		}
	}
	doc["mcpServers"] = servers
	after, _ := json.Marshal(doc)
	w.d.files[c.ConfigPath] = after
	return nil
}

// fakeJournal is the in-memory mcp_relay_launch_spec + backup-file seam.
type fakeJournal struct {
	d          *disk
	rows       map[string]JournalRow
	backups    map[string][]byte
	backupN    int
	backupErr  error
	putErr     error
	putErrOn   string // entry key that fails ("" = every put)
	puts       int
	restoreErr error
}

func newFakeJournal(d *disk) *fakeJournal {
	return &fakeJournal{d: d, rows: map[string]JournalRow{}, backups: map[string][]byte{}}
}

func (j *fakeJournal) List(context.Context) ([]JournalRow, error) {
	var out []JournalRow
	for _, r := range j.rows {
		out = append(out, r)
	}
	sort.Slice(out, func(a, b int) bool {
		return rowKey(out[a].Tool, out[a].ConfigPath, out[a].EntryKey) < rowKey(out[b].Tool, out[b].ConfigPath, out[b].EntryKey)
	})
	return out, nil
}

func (j *fakeJournal) Put(_ context.Context, row JournalRow, expected int64) error {
	j.d.log = append(j.d.log, "put:"+row.Tool+"/"+row.EntryKey)
	if j.putErr != nil && (j.putErrOn == "" || j.putErrOn == row.EntryKey) {
		return j.putErr
	}
	k := rowKey(row.Tool, row.ConfigPath, row.EntryKey)
	if ex, ok := j.rows[k]; ok {
		if ex.ConfigGeneration != expected {
			return fmt.Errorf("conflict: generation %d != expected %d", ex.ConfigGeneration, expected)
		}
	} else if expected != 0 {
		return fmt.Errorf("conflict: no row, expected generation %d", expected)
	}
	j.puts++
	j.rows[k] = row
	return nil
}

func (j *fakeJournal) Delete(_ context.Context, tool, path, key string) error {
	delete(j.rows, rowKey(tool, path, key))
	return nil
}

func (j *fakeJournal) Backup(_ context.Context, c Client, original []byte) (string, string, error) {
	j.d.log = append(j.d.log, "backup:"+c.Tool)
	if j.backupErr != nil {
		return "", "", j.backupErr
	}
	j.backupN++
	p := fmt.Sprintf("bak:%s:%d", c.Tool, j.backupN)
	if original == nil {
		j.backups[p] = nil
		p += ".absent"
		j.backups[p] = nil
	} else {
		j.backups[p] = append([]byte(nil), original...)
	}
	return p, sha(original), nil
}

func (j *fakeJournal) RestoreWhole(_ context.Context, c Client, row JournalRow) error {
	j.d.log = append(j.d.log, "restorewhole:"+c.Tool)
	if j.restoreErr != nil {
		return j.restoreErr
	}
	if row.AppliedSHA256 == "" {
		return ErrNoAppliedDigest
	}
	raw, ok := j.backups[row.BackupPath]
	if !ok || sha(raw) != row.BackupSHA256 {
		return errors.New("backup mismatch")
	}
	if sha(j.d.files[c.ConfigPath]) != row.AppliedSHA256 {
		return fmt.Errorf("%w: %s", ErrConfigChanged, c.ConfigPath)
	}
	if strings.HasSuffix(row.BackupPath, ".absent") {
		delete(j.d.files, c.ConfigPath)
		return nil
	}
	j.d.files[c.ConfigPath] = append([]byte(nil), raw...)
	return nil
}

var (
	claude  = Client{Tool: "claude-code", ConfigPath: "/h/.claude.json", Format: "mcp_servers_json", Verified: true}
	cursor  = Client{Tool: "cursor", ConfigPath: "/h/.cursor/mcp.json", Format: "mcp_servers_json", Verified: true}
	unverif = Client{Tool: "hermes", ConfigPath: "/h/.hermes/config.yaml", Format: "hermes_config_yaml", Verified: false}
	noPath  = Client{Tool: "zed", Format: "x", Verified: true}
	wrap    = WrapSpec{Command: "/usr/local/bin/observer", ConfigPath: "/h/.observer/config.toml"}
	remotes = []RemoteEntry{
		{Name: "superbased-gh", URL: "http://127.0.0.1:8858/mcp/gh", Transport: "http"},
	}
	// approvedAll is the accepted registry the fixtures bind against: gh is
	// a member of vs-gh (slug github), fs the only member of vs-fs, later
	// the only member of vs-later.
	approvedAll = []ApprovedServer{
		{VServer: "vs-gh", VServerSlug: "github", ServerID: "gh", Target: "https://mcp.github.com/mcp"},
		{VServer: "vs-fs", VServerSlug: "files", ServerID: "fs"},
		{VServer: "vs-later", ServerID: "later"},
	}
	desiredAll = Desired{Wrap: &wrap, Remote: remotes, Approved: approvedAll}
	// cursorPrior: two stdio servers (one with an env VALUE), observer's own
	// server, a remote sibling and an unrelated top-level key.
	cursorPrior = `{"mcpServers":{"gh":{"command":"npx","args":["-y","gh-mcp"],"env":{"GITHUB_TOKEN":"ghp_SECRETVALUE"}},"fs":{"command":"/opt/fs","args":["--root","/repo"],"cwd":"/repo"},"observer":{"command":"/usr/local/bin/observer","args":["serve"]},"rem":{"url":"https://x/mcp"}},"theme":"dark"}`
)

func newEnv(t *testing.T) (*disk, *fakeWriter, *fakeJournal, *Projector) {
	t.Helper()
	d := newDisk()
	w := &fakeWriter{d: d}
	j := newFakeJournal(d)
	return d, w, j, &Projector{Writer: w, Journal: j}
}

func serversOf(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v: %s", err, raw)
	}
	out := map[string]map[string]any{}
	for k, v := range doc["mcpServers"].(map[string]any) {
		out[k] = v.(map[string]any)
	}
	return out
}

// TestPlanTable pins the skip rules and the desired-state refusals.
func TestPlanTable(t *testing.T) {
	ops, err := Plan([]Client{claude, unverif, noPath, {Tool: "x", ConfigPath: "/p", Verified: true}}, desiredAll)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", "unverified", "no_config_path", "no_format"}
	for i, op := range ops {
		if op.Skip != want[i] {
			t.Errorf("op %d skip = %q, want %q", i, op.Skip, want[i])
		}
	}
	cases := []struct {
		name string
		d    Desired
		err  error
	}{
		{"authorization header (any case)", Desired{Remote: []RemoteEntry{{Name: "a", URL: "https://x", Headers: map[string]string{" AuthORIZation ": "b"}}}}, ErrCredential},
		{"duplicate name", Desired{Remote: []RemoteEntry{{Name: "a", URL: "https://x"}, {Name: "a", URL: "https://y"}}}, ErrDuplicate},
		{"plain http non-loopback", Desired{Remote: []RemoteEntry{{Name: "a", URL: "http://evil/mcp"}}}, ErrBadEndpoint},
		{"empty url", Desired{Remote: []RemoteEntry{{Name: "a"}}}, ErrBadEndpoint},
		{"wrap without command", Desired{Wrap: &WrapSpec{}}, ErrNoWrapCmd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Plan([]Client{claude}, tc.d); !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
		})
	}
	if _, err := Plan(nil, Desired{Remote: []RemoteEntry{{Name: "a", URL: "https://x", Transport: "ws"}}}); err == nil {
		t.Fatal("bad transport accepted")
	}
}

// TestApplySequenceJournalsBeforeWrite pins the §12.1 order per client
// (stage -> backup -> journal rows -> commit), the row shapes (env KEY
// names only, never the value; the remote sentinel), the applied digest,
// and that observer's own server / a remote sibling are never wrapped.
func TestApplySequenceJournalsBeforeWrite(t *testing.T) {
	ctx := context.Background()
	d, w, j, p := newEnv(t)
	d.files[cursor.ConfigPath] = []byte(cursorPrior)

	rep, err := p.Apply(ctx, []Client{claude, cursor, unverif}, desiredAll)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fingerprint == "" || rep.Fingerprint != Fingerprint(desiredAll) {
		t.Fatal("fingerprint")
	}
	if len(rep.Receipts) != 3 || rep.Receipts[2].Skipped != "unverified" {
		t.Fatalf("receipts %+v", rep.Receipts)
	}
	cc, cu := rep.Receipts[0], rep.Receipts[1]
	if !cc.Changed || cc.Err != "" || len(cc.Wrapped) != 0 || len(cc.Remote) != 1 || cc.BackupPath == "" {
		t.Fatalf("claude receipt %+v", cc)
	}
	if !cu.Changed || cu.Err != "" || strings.Join(cu.Wrapped, ",") != "fs,gh" || len(cu.Remote) != 1 || cu.BackupPath == "" {
		t.Fatalf("cursor receipt %+v", cu)
	}
	if cu.AppliedSHA256 != sha(d.files[cursor.ConfigPath]) {
		t.Fatal("applied digest is not the digest of the bytes written")
	}
	// Order per client: stage, backup, put..., commit - never a commit
	// before its rows, never a row before its backup.
	want := []string{
		"stage:claude-code", "backup:claude-code", "put:claude-code/superbased-gh", "commit:claude-code",
		"stage:cursor", "backup:cursor", "put:cursor/fs", "put:cursor/gh", "put:cursor/superbased-gh", "commit:cursor",
	}
	if got := strings.Join(d.log, " "); got != strings.Join(want, " ") {
		t.Fatalf("seam order:\n got %s\nwant %s", got, strings.Join(want, " "))
	}
	rows, _ := j.List(ctx)
	if len(rows) != 4 {
		t.Fatalf("rows %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.ConfigGeneration != 1 || r.AppliedSHA256 == "" || r.BackupPath == "" || r.AppliedAt.IsZero() {
			t.Fatalf("row shape %+v", r)
		}
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "SECRETVALUE") {
			t.Fatalf("a secret VALUE reached the journal: %s", raw)
		}
		switch r.EntryKey {
		case "gh":
			if r.Kind() != RowStdioWrap || r.OrigCommand != "npx" || strings.Join(r.OrigArgs, " ") != "-y gh-mcp" || strings.Join(r.OrigEnvRefs, ",") != "GITHUB_TOKEN" {
				t.Fatalf("gh row %+v", r)
			}
		case "fs":
			if r.OrigCwd != "/repo" || r.OrigCommand != "/opt/fs" {
				t.Fatalf("fs row %+v", r)
			}
		case "superbased-gh":
			if r.Kind() != RowRemote || r.OrigCommand != RemoteOrigCommand {
				t.Fatalf("remote row %+v", r)
			}
		default:
			t.Fatalf("unexpected row %+v", r)
		}
	}
	// The cursor rows share ONE backup holding the verbatim original.
	for _, r := range rows {
		if r.Tool != "cursor" {
			continue
		}
		if string(j.backups[r.BackupPath]) != cursorPrior || r.BackupSHA256 != sha([]byte(cursorPrior)) {
			t.Fatalf("backup %q for %+v", j.backups[r.BackupPath], r)
		}
	}
	// The file: gh + fs wrapped (env VALUE still there for the client to
	// hand the wrapper), observer + rem untouched, remote added, theme kept.
	s := serversOf(t, d.files[cursor.ConfigPath])
	if s["gh"]["command"] != wrap.Command || fmt.Sprint(s["gh"]["args"]) != fmt.Sprint([]any{"mcp-relay", "wrap", "--client", "cursor", "--server", "gh", "--config", wrap.ConfigPath}) {
		t.Fatalf("gh not wrapped: %v", s["gh"])
	}
	if s["gh"]["env"].(map[string]any)["GITHUB_TOKEN"] != "ghp_SECRETVALUE" || s["fs"]["cwd"] != "/repo" {
		t.Fatalf("entry fields not preserved: %v %v", s["gh"], s["fs"])
	}
	if s["observer"]["command"] != "/usr/local/bin/observer" || fmt.Sprint(s["observer"]["args"]) != "[serve]" || s["rem"]["url"] != "https://x/mcp" || s["superbased-gh"]["url"] != remotes[0].URL {
		t.Fatalf("siblings: %v", s)
	}

	// Idempotent: same desired state again => nothing staged as changed, no
	// backup, no row, no commit.
	d.log = nil
	rep2, err := p.Apply(ctx, []Client{claude, cursor}, desiredAll)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep2.Receipts {
		if r.Changed || r.Err != "" {
			t.Fatalf("second apply must be a no-op: %+v", r)
		}
	}
	if j.puts != 4 || w.commits != 2 || j.backupN != 2 || strings.Contains(strings.Join(d.log, " "), "backup") {
		t.Fatalf("second apply touched the journal: puts=%d commits=%d backups=%d log=%v", j.puts, w.commits, j.backupN, d.log)
	}
	// Fingerprint is order-independent over the remote set.
	rev := Desired{Wrap: &wrap, Remote: []RemoteEntry{{Name: "b", URL: "https://b"}, {Name: "a", URL: "https://a"}}}
	fwd := Desired{Wrap: &wrap, Remote: []RemoteEntry{{Name: "a", URL: "https://a"}, {Name: "b", URL: "https://b"}}}
	if Fingerprint(rev) != Fingerprint(fwd) {
		t.Fatal("fingerprint must be order-independent")
	}
}

// TestApplyCrashBoundaries: a failure at each of the three §12.1 steps
// leaves the config untouched, and a re-run completes the projection
// under the SAME backup (first write wins) - the recovery §12.1 names.
func TestApplyCrashBoundaries(t *testing.T) {
	ctx := context.Background()
	if _, err := (&Projector{Writer: &fakeWriter{d: newDisk()}}).Apply(ctx, []Client{claude}, desiredAll); !errors.Is(err, ErrNoJournal) {
		t.Fatalf("no journal: %v", err)
	}
	if _, err := (&Projector{Journal: newFakeJournal(newDisk())}).Apply(ctx, []Client{claude}, desiredAll); !errors.Is(err, ErrNoWriter) {
		t.Fatalf("no writer: %v", err)
	}
	boom := errors.New("disk full")
	cases := []struct {
		name    string
		arm     func(w *fakeWriter, j *fakeJournal)
		disarm  func(w *fakeWriter, j *fakeJournal)
		rows    int // rows left after the failed apply
		errPart string
	}{
		{"step 1 backup fails: no row, no write", func(_ *fakeWriter, j *fakeJournal) { j.backupErr = boom }, func(_ *fakeWriter, j *fakeJournal) { j.backupErr = nil }, 0, "backup:"},
		{"step 2 journal row fails: no write", func(_ *fakeWriter, j *fakeJournal) { j.putErr = boom; j.putErrOn = "gh" }, func(_ *fakeWriter, j *fakeJournal) { j.putErr = nil }, 1, "journal gh:"},
		{"step 3 commit fails: rows retained, file untouched", func(w *fakeWriter, _ *fakeJournal) { w.commitErr = boom }, func(w *fakeWriter, _ *fakeJournal) { w.commitErr = nil }, 3, "commit:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, w, j, p := newEnv(t)
			d.files[cursor.ConfigPath] = []byte(cursorPrior)
			tc.arm(w, j)
			rep, err := p.Apply(ctx, []Client{cursor}, desiredAll)
			if err != nil {
				t.Fatal(err)
			}
			r := rep.Receipts[0]
			if r.Changed || !strings.Contains(r.Err, tc.errPart) {
				t.Fatalf("receipt %+v", r)
			}
			if string(d.files[cursor.ConfigPath]) != cursorPrior || w.commits != 0 {
				t.Fatal("config touched by a failed step")
			}
			rows, _ := j.List(ctx)
			if len(rows) != tc.rows {
				t.Fatalf("rows after failure = %d, want %d", len(rows), tc.rows)
			}
			// Recovery: re-run completes under the same backup.
			tc.disarm(w, j)
			rep, err = p.Apply(ctx, []Client{cursor}, desiredAll)
			if err != nil || !rep.Receipts[0].Changed || rep.Receipts[0].Err != "" {
				t.Fatalf("recovery %+v %v", rep.Receipts[0], err)
			}
			rows, _ = j.List(ctx)
			if len(rows) != 3 {
				t.Fatalf("rows after recovery %d", len(rows))
			}
			for _, row := range rows {
				if row.ConfigGeneration != 1 || row.BackupSHA256 != sha([]byte(cursorPrior)) || string(j.backups[row.BackupPath]) != cursorPrior || row.AppliedSHA256 != sha(d.files[cursor.ConfigPath]) {
					t.Fatalf("recovered row %+v", row)
				}
			}
			if s := serversOf(t, d.files[cursor.ConfigPath]); s["gh"]["command"] != wrap.Command {
				t.Fatal("not wrapped after recovery")
			}
			// The recovered group is still ONE write event (a retry of an
			// unlanded write keeps generation 1), so a disable restores it
			// byte-identically.
			recs, rerr := p.Restore(ctx)
			if rerr != nil || len(recs) != 1 || recs[0].Mode != RestoreWholeFile || string(d.files[cursor.ConfigPath]) != cursorPrior {
				t.Fatalf("restore after recovery: %+v %v %s", recs, rerr, d.files[cursor.ConfigPath])
			}
		})
	}
	// A commit CAS refusal: the file moved between Stage and Commit.
	d, w, j, p := newEnv(t)
	d.files[cursor.ConfigPath] = []byte(cursorPrior)
	w.commitErr = fmt.Errorf("%w: %s", ErrConfigChanged, cursor.ConfigPath)
	rep, _ := p.Apply(ctx, []Client{cursor}, desiredAll)
	if rep.Receipts[0].Changed || !strings.Contains(rep.Receipts[0].Err, "changed underneath") {
		t.Fatalf("%+v", rep.Receipts[0])
	}
	_ = j
	// A stage failure is per client; the loop continues.
	d2, w2, _, p2 := newEnv(t)
	d2.files[cursor.ConfigPath] = []byte(cursorPrior)
	w2.stageErr = errors.New("unparseable")
	rep, _ = p2.Apply(ctx, []Client{claude, cursor}, desiredAll)
	if len(rep.Receipts) != 2 || rep.Receipts[0].Err == "" || rep.Receipts[1].Err == "" || w2.commits != 0 {
		t.Fatalf("%+v", rep.Receipts)
	}
}

// TestRestoreRuleTable is the restore decision table's one-case-per-row
// test plus the CAS fallback: untouched -> whole-file byte-identical; an
// edit between projection and disable -> whole-file REFUSED, reversal
// applied, the edit preserved; a pre-132 row -> reversal; several write
// events -> reversal; a refused reversal keeps the rows.
func TestRestoreRuleTable(t *testing.T) {
	ctx := context.Background()
	project := func(t *testing.T) (*disk, *fakeWriter, *fakeJournal, *Projector) {
		t.Helper()
		d, w, j, p := newEnv(t)
		d.files[cursor.ConfigPath] = []byte(cursorPrior)
		if _, err := p.Apply(ctx, []Client{claude, cursor}, desiredAll); err != nil {
			t.Fatal(err)
		}
		return d, w, j, p
	}
	t.Run("untouched: whole-file byte-identical, absent file removed", func(t *testing.T) {
		d, _, j, p := project(t)
		recs, err := p.Restore(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != 2 {
			t.Fatalf("%+v", recs)
		}
		for _, r := range recs {
			if !r.Restored || r.Mode != RestoreWholeFile || r.Rule != "single_write_event" || r.Note != "" {
				t.Fatalf("%+v", r)
			}
		}
		if string(d.files[cursor.ConfigPath]) != cursorPrior {
			t.Fatalf("not byte-identical: %s", d.files[cursor.ConfigPath])
		}
		if _, ok := d.files[claude.ConfigPath]; ok {
			t.Fatal("claude config must be removed (did not exist before)")
		}
		if rows, _ := j.List(ctx); len(rows) != 0 {
			t.Fatalf("rows not deleted: %+v", rows)
		}
	})
	t.Run("edited after projection: whole-file refused, reversal preserves the edit", func(t *testing.T) {
		d, _, j, p := project(t)
		var doc map[string]any
		_ = json.Unmarshal(d.files[cursor.ConfigPath], &doc)
		doc["theme"] = "light"
		doc["mcpServers"].(map[string]any)["added-later"] = map[string]any{"command": "/opt/new"}
		d.files[cursor.ConfigPath], _ = json.Marshal(doc)
		d.log = nil
		recs, err := p.Restore(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var cu RestoreReceipt
		for _, r := range recs {
			if r.Client.Tool == "cursor" {
				cu = r
			}
		}
		if !cu.Restored || cu.Mode != RestoreReversal || cu.Rule != "single_write_event" || !strings.Contains(cu.Note, "whole-file restore refused") {
			t.Fatalf("%+v", cu)
		}
		if !strings.Contains(strings.Join(d.log, " "), "restorewhole:cursor revert:cursor") {
			t.Fatalf("expected whole-file attempt then reversal: %v", d.log)
		}
		s := serversOf(t, d.files[cursor.ConfigPath])
		if s["gh"]["command"] != "npx" || fmt.Sprint(s["gh"]["args"]) != "[-y gh-mcp]" || s["fs"]["command"] != "/opt/fs" {
			t.Fatalf("originals not back: %v", s)
		}
		if _, ok := s["superbased-gh"]; ok {
			t.Fatal("relay remote entry not deleted")
		}
		if s["added-later"]["command"] != "/opt/new" || s["observer"]["command"] != "/usr/local/bin/observer" {
			t.Fatalf("post-projection edit lost: %v", s)
		}
		var after map[string]any
		_ = json.Unmarshal(d.files[cursor.ConfigPath], &after)
		if after["theme"] != "light" {
			t.Fatal("unrelated edit lost")
		}
		if rows, _ := j.List(ctx); len(rows) != 0 {
			t.Fatalf("rows not deleted after reversal: %+v", rows)
		}
	})
	t.Run("pre-132 row: reversal, never whole-file", func(t *testing.T) {
		d, _, j, p := project(t)
		for k, r := range j.rows {
			if r.Tool == "cursor" {
				r.AppliedSHA256 = ""
				j.rows[k] = r
			}
		}
		d.log = nil
		recs, _ := p.Restore(ctx)
		for _, r := range recs {
			if r.Client.Tool == "cursor" && (r.Rule != "legacy_row_no_applied_digest" || r.Mode != RestoreReversal || !r.Restored) {
				t.Fatalf("%+v", r)
			}
		}
		if strings.Contains(strings.Join(d.log, " "), "restorewhole:cursor") {
			t.Fatal("whole-file restore attempted on a legacy row")
		}
	})
	t.Run("several write events: reversal", func(t *testing.T) {
		d, _, j, p := project(t)
		// A second write event: the operator adds a stdio server, the daemon
		// re-projects (new row, new backup holding already-wrapped entries).
		var doc map[string]any
		_ = json.Unmarshal(d.files[cursor.ConfigPath], &doc)
		doc["mcpServers"].(map[string]any)["later"] = map[string]any{"command": "/opt/later"}
		d.files[cursor.ConfigPath], _ = json.Marshal(doc)
		if _, err := p.Apply(ctx, []Client{cursor}, desiredAll); err != nil {
			t.Fatal(err)
		}
		rows, _ := j.List(ctx)
		if len(rows) != 5 {
			t.Fatalf("rows %d", len(rows))
		}
		// Un-wrap gh by hand and re-project: the file no longer holds the
		// pre-relay bytes, so this IS a new write event -> generation 2.
		_ = json.Unmarshal(d.files[cursor.ConfigPath], &doc)
		doc["mcpServers"].(map[string]any)["gh"] = map[string]any{"command": "npx", "args": []any{"-y", "gh-mcp"}}
		d.files[cursor.ConfigPath], _ = json.Marshal(doc)
		if _, err := p.Apply(ctx, []Client{cursor}, desiredAll); err != nil {
			t.Fatal(err)
		}
		rows, _ = j.List(ctx)
		for _, r := range rows {
			if r.EntryKey == "gh" && r.ConfigGeneration != 2 {
				t.Fatalf("re-wrap after the file changed must bump the generation: %+v", r)
			}
		}
		d.log = nil
		recs, err := p.Restore(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if r.Client.Tool == "cursor" && (r.Rule != "multi_write_event" || r.Mode != RestoreReversal || !r.Restored) {
				t.Fatalf("%+v", r)
			}
		}
		if strings.Contains(strings.Join(d.log, " "), "restorewhole:cursor") {
			t.Fatal("whole-file restore attempted over several write events (would drop the later server)")
		}
		s := serversOf(t, d.files[cursor.ConfigPath])
		if s["later"]["command"] != "/opt/later" || s["gh"]["command"] != "npx" {
			t.Fatalf("%v", s)
		}
	})
	t.Run("refused reversal keeps rows and backup", func(t *testing.T) {
		d, w, j, p := project(t)
		d.files[cursor.ConfigPath] = append(d.files[cursor.ConfigPath], ' ')
		w.revertErr = fmt.Errorf("%w: %s", ErrConfigChanged, cursor.ConfigPath)
		recs, err := p.Restore(ctx)
		if err == nil {
			t.Fatal("want an error")
		}
		for _, r := range recs {
			if r.Client.Tool == "cursor" && (r.Restored || !strings.Contains(r.Err, "changed underneath")) {
				t.Fatalf("%+v", r)
			}
		}
		rows, _ := j.List(ctx)
		if len(rows) != 3 {
			t.Fatalf("rows dropped on a refused restore: %d", len(rows))
		}
		if _, ok := j.backups[rows[0].BackupPath]; !ok {
			t.Fatal("backup dropped on a refused restore")
		}
	})
	if _, err := (&Projector{Writer: &fakeWriter{d: newDisk()}}).Restore(ctx); !errors.Is(err, ErrNoJournal) {
		t.Fatal(err)
	}
}

// TestWrapHelpers pins the wrapper args vector and the two idempotence
// predicates (already-wrapped, and observer's own command).
func TestWrapHelpers(t *testing.T) {
	w := WrapSpec{Command: "/usr/local/bin/observer"}
	if got := WrapArgs("cursor", "gh", w); strings.Join(got, " ") != "mcp-relay wrap --client cursor --server gh" {
		t.Fatalf("%v", got)
	}
	if got := WrapArgs("cursor", "gh", WrapSpec{Command: "x", ConfigPath: "/c.toml"}); strings.Join(got, " ") != "mcp-relay wrap --client cursor --server gh --config /c.toml" {
		t.Fatalf("%v", got)
	}
	cases := []struct {
		cmd     string
		args    []string
		wrapper bool
		obs     bool
	}{
		{"/usr/local/bin/observer", []string{"mcp-relay", "wrap", "--client", "c", "--server", "s"}, true, true},
		{"/usr/local/bin/observer", []string{"serve"}, false, true},
		{"observer", []string{"serve"}, false, true},
		{"C:\\tools\\observer.exe", nil, false, true},
		{"/other/observer", []string{"mcp-relay", "wrap"}, false, true},
		{"npx", []string{"mcp-relay", "wrap"}, false, false},
		{"npx", []string{"-y", "gh"}, false, false},
		{"", nil, false, false},
	}
	for _, tc := range cases {
		if got := IsWrapper(tc.cmd, tc.args, w); got != tc.wrapper {
			t.Errorf("IsWrapper(%q,%v) = %v", tc.cmd, tc.args, got)
		}
		if got := IsObserver(tc.cmd, w); got != tc.obs {
			t.Errorf("IsObserver(%q) = %v", tc.cmd, got)
		}
	}
	rows := []JournalRow{{Tool: "cursor"}, {Tool: "cursor"}, {Tool: "codex", OrigCommand: RemoteOrigCommand}}
	ap := Applied(rows)
	if !ap["cursor"] || !ap["codex"] || ap["claude-code"] {
		t.Fatalf("%v", ap)
	}
	if rows[2].Kind() != RowRemote || rows[0].Kind() != RowStdioWrap {
		t.Fatal("kinds")
	}
}

// TestBindTable is the binding rule table (Sol P3+P4 fold finding 2): one
// case per matcher row and per typed refusal. Never a guess.
func TestBindTable(t *testing.T) {
	multi := []ApprovedServer{
		{VServer: "vs-dev", VServerSlug: "dev", ServerID: "gh", Target: "https://gh"},
		{VServer: "vs-dev", VServerSlug: "dev", ServerID: "jira", Target: "jira-cmd"},
		{VServer: "vs-ops", VServerSlug: "ops", ServerID: "pager", Target: "gh"},
		{VServer: "vs-empty", VServerSlug: "empty"},
	}
	cases := []struct {
		name     string
		approved []ApprovedServer
		key      string
		want     Binding
		refusal  string
	}{
		{"member server id", approvedAll, "gh", Binding{VServer: "vs-gh", ServerID: "gh"}, ""},
		{"member target", approvedAll, "https://mcp.github.com/mcp", Binding{VServer: "vs-gh", ServerID: "gh"}, ""},
		{"vserver id -> its only member", approvedAll, "vs-fs", Binding{VServer: "vs-fs", ServerID: "fs"}, ""},
		{"vserver slug -> its only member", approvedAll, "github", Binding{VServer: "vs-gh", ServerID: "gh"}, ""},
		{"vserver with no member binds member-less", multi, "empty", Binding{VServer: "vs-empty"}, ""},
		{"no approved servers (no table)", nil, "gh", Binding{}, RefuseNoApprovedServers},
		{"key names nothing approved", approvedAll, "slack", Binding{}, RefuseNoBinding},
		{"empty key", approvedAll, "", Binding{}, RefuseNoBinding},
		{"key spans two vservers (id in one, target in another)", multi, "gh", Binding{}, RefuseAmbiguousVServer},
		{"vserver-level match on a multi-member vserver", multi, "dev", Binding{}, RefuseAmbiguousServer},
		{"one member of a multi-member vserver by id", multi, "jira", Binding{VServer: "vs-dev", ServerID: "jira"}, ""},
		{"one member of a multi-member vserver by target", multi, "jira-cmd", Binding{VServer: "vs-dev", ServerID: "jira"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, refusal := Bind(tc.approved, tc.key)
			if got != tc.want || refusal != tc.refusal {
				t.Fatalf("Bind(%q) = %+v %q, want %+v %q", tc.key, got, refusal, tc.want, tc.refusal)
			}
		})
	}
	// Two members' id / target colliding inside ONE vserver: ambiguous.
	collide := []ApprovedServer{{VServer: "v", ServerID: "a", Target: "b"}, {VServer: "v", ServerID: "b"}}
	if _, r := Bind(collide, "b"); r != RefuseAmbiguousServer {
		t.Fatalf("collision = %q", r)
	}
}

// TestApplyBindsOrRefusesEveryStdioEntry: a bound entry is wrapped and its
// row carries the approved (vserver, registry server) binding; an unbound
// entry is NOT wrapped, stays direct and is reported with the typed
// reason; a table-less node wraps nothing; a writer that ignores the
// binding has its write refused (the projector never journals an entry the
// wrapper could not authorize).
func TestApplyBindsOrRefusesEveryStdioEntry(t *testing.T) {
	ctx := context.Background()
	prior := `{"mcpServers":{"gh":{"command":"npx","args":["-y","gh-mcp"]},"slack":{"command":"/opt/slack"},"observer":{"command":"/usr/local/bin/observer","args":["serve"]}}}`
	d, _, j, p := newEnv(t)
	d.files[cursor.ConfigPath] = []byte(prior)
	rep, err := p.Apply(ctx, []Client{cursor}, Desired{Wrap: &wrap, Approved: approvedAll})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Receipts[0]
	if !r.Changed || r.Err != "" || strings.Join(r.Wrapped, ",") != "gh" {
		t.Fatalf("receipt %+v", r)
	}
	if len(r.Refused) != 1 || r.Refused[0] != (EntryRefusal{Key: "slack", Reason: RefuseNoBinding}) {
		t.Fatalf("refused %+v", r.Refused)
	}
	rows, _ := j.List(ctx)
	if len(rows) != 1 || rows[0].EntryKey != "gh" || rows[0].VServer != "vs-gh" || rows[0].RegistryServerID != "gh" {
		t.Fatalf("rows %+v", rows)
	}
	s := serversOf(t, d.files[cursor.ConfigPath])
	if s["gh"]["command"] != wrap.Command || s["slack"]["command"] != "/opt/slack" {
		t.Fatalf("file %v", s)
	}
	// A caller-supplied Bind is replaced by the projector's authority.
	d2, _, j2, p2 := newEnv(t)
	d2.files[cursor.ConfigPath] = []byte(prior)
	evil := wrap
	evil.Bind = func(string) (Binding, string) { return Binding{VServer: "vs-gh"}, "" }
	rep, _ = p2.Apply(ctx, []Client{cursor}, Desired{Wrap: &evil, Approved: approvedAll})
	if rows, _ := j2.List(ctx); len(rows) != 1 || rep.Receipts[0].Refused[0].Key != "slack" {
		t.Fatalf("caller Bind was honoured: %+v %+v", rows, rep.Receipts[0])
	}
	// No accepted table: nothing is wrapped, every stdio entry refused.
	d3, w3, j3, p3 := newEnv(t)
	d3.files[cursor.ConfigPath] = []byte(prior)
	rep, _ = p3.Apply(ctx, []Client{cursor}, Desired{Wrap: &wrap})
	r = rep.Receipts[0]
	if r.Changed || w3.commits != 0 || len(r.Refused) != 2 || r.Refused[0].Reason != RefuseNoApprovedServers {
		t.Fatalf("table-less apply %+v", r)
	}
	if rows, _ := j3.List(ctx); len(rows) != 0 || string(d3.files[cursor.ConfigPath]) != prior {
		t.Fatal("table-less apply journaled or wrote")
	}
	// A writer that ignores the binding: the write is refused.
	d4, w4, j4, p4 := newEnv(t)
	w4.ignoreBind = true
	d4.files[cursor.ConfigPath] = []byte(prior)
	rep, _ = p4.Apply(ctx, []Client{cursor}, Desired{Wrap: &wrap, Approved: approvedAll})
	if r := rep.Receipts[0]; r.Changed || !strings.Contains(r.Err, "binds to no approved server") || w4.commits != 0 {
		t.Fatalf("unbound wrap not refused: %+v", r)
	}
	if rows, _ := j4.List(ctx); len(rows) != 0 || string(d4.files[cursor.ConfigPath]) != prior {
		t.Fatal("a refused stage journaled or wrote")
	}
}

// TestVerifyAppliedPerTransport pins finding 3's predicate: separate
// stdio / remote truth, a row counts only when the config's CURRENT bytes
// are what the relay wrote.
func TestVerifyAppliedPerTransport(t *testing.T) {
	ctx := context.Background()
	digestOf := func(d *disk) func(string) (string, bool) {
		return func(p string) (string, bool) {
			b, ok := d.files[p]
			if !ok {
				return "", false
			}
			return sha(b), true
		}
	}
	stdioOnly := `{"mcpServers":{"gh":{"command":"npx"}}}`

	t.Run("stdio-only projection: stdio applied, remote NOT", func(t *testing.T) {
		d, _, j, p := newEnv(t)
		d.files[cursor.ConfigPath] = []byte(stdioOnly)
		if _, err := p.Apply(ctx, []Client{cursor}, Desired{Wrap: &wrap, Approved: approvedAll}); err != nil {
			t.Fatal(err)
		}
		rows, _ := j.List(ctx)
		a := VerifyApplied(rows, digestOf(d))
		if !a.StdioApplied("cursor") || a.RemoteApplied("cursor") || !a.Any() || strings.Join(a.Clients(), ",") != "cursor" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("remote-only projection: remote applied, stdio NOT", func(t *testing.T) {
		d, _, j, p := newEnv(t)
		if _, err := p.Apply(ctx, []Client{claude}, Desired{Remote: remotes}); err != nil {
			t.Fatal(err)
		}
		rows, _ := j.List(ctx)
		a := VerifyApplied(rows, digestOf(d))
		if a.StdioApplied("claude-code") || !a.RemoteApplied("claude-code") {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("stage + journal ok, commit fails: NOT applied", func(t *testing.T) {
		d, w, j, p := newEnv(t)
		d.files[cursor.ConfigPath] = []byte(stdioOnly)
		w.commitErr = errors.New("rename: read-only file system")
		rep, _ := p.Apply(ctx, []Client{cursor}, desiredAll)
		rows, _ := j.List(ctx)
		if len(rows) == 0 || rep.Receipts[0].Err == "" {
			t.Fatalf("expected retained rows + a commit error: %+v", rep.Receipts[0])
		}
		a := VerifyApplied(rows, digestOf(d))
		if a.Any() || a.StdioApplied("cursor") || a.RemoteApplied("cursor") {
			t.Fatalf("a failed commit counted as applied: %+v", a)
		}
		// Legacy view still lists it - which is exactly why it is not the
		// predicate.
		if !Applied(rows)["cursor"] {
			t.Fatal("Applied fixture")
		}
	})
	t.Run("edited since, unreadable, pre-132: NOT applied", func(t *testing.T) {
		d, _, j, p := newEnv(t)
		d.files[cursor.ConfigPath] = []byte(stdioOnly)
		if _, err := p.Apply(ctx, []Client{cursor}, desiredAll); err != nil {
			t.Fatal(err)
		}
		rows, _ := j.List(ctx)
		d.files[cursor.ConfigPath] = append(d.files[cursor.ConfigPath], ' ')
		if a := VerifyApplied(rows, digestOf(d)); a.Any() {
			t.Fatalf("edited config counted: %+v", a)
		}
		if a := VerifyApplied(rows, func(string) (string, bool) { return "", false }); a.Any() {
			t.Fatal("unreadable config counted")
		}
		legacy := append([]JournalRow(nil), rows...)
		for i := range legacy {
			legacy[i].AppliedSHA256 = ""
		}
		if a := VerifyApplied(legacy, func(string) (string, bool) { return "", true }); a.Any() {
			t.Fatal("pre-132 row counted")
		}
		if a := VerifyApplied(rows, nil); a.Any() {
			t.Fatal("nil digest seam counted")
		}
	})
	t.Run("stdio then remote: earlier rows refreshed, both applied; edit in between is not refreshed", func(t *testing.T) {
		d, _, j, p := newEnv(t)
		d.files[cursor.ConfigPath] = []byte(stdioOnly)
		if _, err := p.Apply(ctx, []Client{cursor}, Desired{Wrap: &wrap, Approved: approvedAll}); err != nil {
			t.Fatal(err)
		}
		rep, err := p.Apply(ctx, []Client{cursor}, desiredAll)
		if err != nil || !rep.Receipts[0].Changed || rep.Receipts[0].Note != "" {
			t.Fatalf("%+v %v", rep.Receipts, err)
		}
		rows, _ := j.List(ctx)
		a := VerifyApplied(rows, digestOf(d))
		if !a.StdioApplied("cursor") || !a.RemoteApplied("cursor") {
			t.Fatalf("second write event lost the stdio row: %+v rows=%+v", a, rows)
		}
		for _, r := range rows {
			if r.ConfigGeneration != 1 {
				t.Fatalf("refresh bumped a generation: %+v", r)
			}
		}
		// Restore still reverses (two write events, two backups).
		recs, err := p.Restore(ctx)
		if err != nil || recs[0].Mode != RestoreReversal || recs[0].Rule != "multi_write_event" {
			t.Fatalf("restore after refresh: %+v %v", recs, err)
		}

		d2, _, j2, p2 := newEnv(t)
		d2.files[cursor.ConfigPath] = []byte(stdioOnly)
		if _, err := p2.Apply(ctx, []Client{cursor}, Desired{Wrap: &wrap, Approved: approvedAll}); err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.Unmarshal(d2.files[cursor.ConfigPath], &doc)
		doc["theme"] = "light"
		d2.files[cursor.ConfigPath], _ = json.Marshal(doc)
		if _, err := p2.Apply(ctx, []Client{cursor}, desiredAll); err != nil {
			t.Fatal(err)
		}
		rows2, _ := j2.List(ctx)
		a2 := VerifyApplied(rows2, digestOf(d2))
		if a2.StdioApplied("cursor") || !a2.RemoteApplied("cursor") {
			t.Fatalf("an edit between write events must not be vouched for: %+v", a2)
		}
	})
}

// TestPreviewNeverJournalsOrWrites: Preview stages only - it reports the
// would-wrap and refused entries and never touches the journal or a file.
func TestPreviewNeverJournalsOrWrites(t *testing.T) {
	ctx := context.Background()
	prior := `{"mcpServers":{"gh":{"command":"npx"},"slack":{"command":"/opt/slack"}}}`
	d, w, j, p := newEnv(t)
	d.files[cursor.ConfigPath] = []byte(prior)
	rep, err := p.Preview(ctx, []Client{cursor, unverif}, Desired{Wrap: &wrap, Approved: approvedAll})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Receipts[0]
	if !r.Changed || strings.Join(r.Wrapped, ",") != "gh" || len(r.Refused) != 1 || r.Refused[0].Key != "slack" || rep.Receipts[1].Skipped != "unverified" {
		t.Fatalf("%+v", rep.Receipts)
	}
	if w.commits != 0 || j.puts != 0 || j.backupN != 0 || string(d.files[cursor.ConfigPath]) != prior {
		t.Fatal("preview journaled or wrote")
	}
	if _, err := (&Projector{}).Preview(ctx, nil, Desired{}); !errors.Is(err, ErrNoWriter) {
		t.Fatal(err)
	}
}
