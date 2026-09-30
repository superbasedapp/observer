package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/coverage"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// Sol P3+P4 fold re-review findings 2 + 3, exercised through the
// PRODUCTION composition: the real per-format writer projects a real client
// config (key `gh` under the committed fixture's vserver `vs-gh`), the real
// migrated journal persists the approved binding, launchSpecsFromJournal
// resolves it, and the relay's stdio wrapper runs a REAL child process under
// the local PDP compiled from the accepted tools.mcp_access table.

// mcpRelayChildEnv switches this test binary into the helper MCP server
// (TestMCPRelayWrapHelperChild) when the wrapper spawns it as the ORIGINAL
// stdio server.
const (
	mcpRelayChildEnv    = "SBO_MCPRELAY_CHILD"
	mcpRelayChildLogEnv = "SBO_MCPRELAY_CHILD_LOG"
)

// TestMCPRelayWrapHelperChild is NOT a test: it is the original stdio MCP
// server the wrapper spawns (this test binary re-executed with
// -test.run=^TestMCPRelayWrapHelperChild$ and mcpRelayChildEnv=1). Every
// frame it receives is logged; a request is answered with a result naming
// the tool it was asked to call.
func TestMCPRelayWrapHelperChild(t *testing.T) {
	if os.Getenv(mcpRelayChildEnv) != "1" {
		t.Skip("helper child process only (spawned by the stdio-wrapper production-composition test)")
	}
	logf, err := os.OpenFile(os.Getenv(mcpRelayChildLogEnv), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	out := bufio.NewWriter(os.Stdout)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(logf, "%s\n", line)
		m, perr := mcprelay.ParseMessage(line)
		if perr != nil || !m.HasID() {
			continue
		}
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(m.Params, &p)
		res, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": m.ID,
			"result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "child:" + p.Name}}},
		})
		_, _ = out.Write(append(res, '\n'))
		_ = out.Flush()
	}
	_ = logf.Close()
	os.Exit(0)
}

// failingCommit wraps the real writer but fails every Commit: stage and
// journal succeed, the config write does not (finding 3's commit-failure
// row).
type failingCommit struct{ project.Writer }

func (failingCommit) Commit(context.Context, project.Client, project.Staged) error {
	return errors.New("rename: read-only file system")
}

// mcpRelayWrapFixture is a private home with a cursor config whose `gh`
// entry spawns this test binary (through a differently named symlink, so it
// is not mistaken for observer's own server) and whose `slack` entry binds
// to no approved server.
type mcpRelayWrapFixture struct {
	home, cursorPath, childLog, childCmd string
	original                             []byte
}

func newMCPRelayWrapFixture(t *testing.T) mcpRelayWrapFixture {
	t.Helper()
	f := mcpRelayWrapFixture{home: t.TempDir(), childLog: filepath.Join(t.TempDir(), "child.log")}
	mcpRelayHomeOverride = f.home
	t.Cleanup(func() { mcpRelayHomeOverride = "" })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f.childCmd = filepath.Join(t.TempDir(), "gh-mcp-server")
	if err := os.Symlink(self, f.childCmd); err != nil {
		t.Fatalf("symlink child: %v", err)
	}
	doc := map[string]any{"mcpServers": map[string]any{
		"gh":    map[string]any{"command": f.childCmd, "args": []string{"-test.run=^TestMCPRelayWrapHelperChild$"}, "env": map[string]string{mcpRelayChildEnv: "1"}},
		"slack": map[string]any{"command": "/opt/slack-mcp", "args": []string{"--stdio"}},
	}}
	f.original, _ = json.MarshalIndent(doc, "", "  ")
	f.cursorPath = filepath.Join(f.home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(f.cursorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cursorPath, f.original, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestMCPRelay_WrappedEntryMediatesThroughProductionComposition is finding
// 2's production-composition proof: project -> journal (binding persisted)
// -> launchSpecsFromJournal (binding populated) -> ServeStdioWrapper with
// the local PDP loaded -> a permitted tools/call REACHES the child and its
// answer flows back; a denied call never reaches the child; an entry with no
// approved binding is skipped with the reason and the matrix says so.
func TestMCPRelay_WrappedEntryMediatesThroughProductionComposition(t *testing.T) {
	ctx := context.Background()
	f := newMCPRelayWrapFixture(t)
	cfg := mcpRelayTestCfg(t, true)
	database, err := dbtemplate.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	rs := record.NewSQLStore(database, "")
	h := appliedHandle(t, cfg, "enforce", false)

	rep, _, err := runMCPRelayProjection(ctx, cfg, "", rs, h, false)
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	var cur project.Receipt
	for _, r := range rep.Receipts {
		if r.Client.Tool == "cursor" {
			cur = r
		}
	}
	if !cur.Changed || cur.Err != "" || strings.Join(cur.Wrapped, ",") != "gh" {
		t.Fatalf("cursor receipt %+v", cur)
	}
	if len(cur.Refused) != 1 || cur.Refused[0] != (project.EntryRefusal{Key: "slack", Reason: project.RefuseNoBinding}) {
		t.Fatalf("slack must be skipped with the typed reason: %+v", cur.Refused)
	}
	var doc map[string]map[string]map[string]any
	raw, _ := os.ReadFile(f.cursorPath)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["mcpServers"]["slack"]["command"] != "/opt/slack-mcp" {
		t.Fatalf("unbound slack entry was rewritten: %v", doc["mcpServers"]["slack"])
	}
	if doc["mcpServers"]["gh"]["command"] == f.childCmd {
		t.Fatalf("gh not wrapped: %v", doc["mcpServers"]["gh"])
	}
	rows, err := rs.ListLaunchSpecs(ctx)
	if err != nil || len(rows) != 1 || rows[0].VServer != "vs-gh" || rows[0].RegistryServerID != "gh" {
		t.Fatalf("journal must hold exactly gh bound to vs-gh/gh: %+v %v", rows, err)
	}

	// The matrix says so: cursor's stdio is verified-projected but slack
	// runs direct, so the client's stdio is NOT mediated.
	cell := func(rows []coverage.Row, tool string, tr coverage.Transport, m coverage.Method) coverage.Row {
		for _, r := range rows {
			if r.Client == tool && r.Transport == tr && r.Method == m {
				return r
			}
		}
		return coverage.Row{}
	}
	matrix := coverage.Matrix(mcpRelayCoverageLive(ctx, cfg, rs, h, false))
	for _, m := range coverage.Methods {
		c := cell(matrix, "cursor", coverage.TransportStdio, m)
		if c.Coverage == coverage.Mediated || !strings.Contains(c.Note, "not wrapped") {
			t.Fatalf("cursor stdio %s with an unbound entry = %+v", m, c)
		}
	}

	// launchSpecsFromJournal: the approved binding rides the launch spec.
	env := append(os.Environ(), mcpRelayChildEnv+"=1", mcpRelayChildLogEnv+"="+f.childLog)
	specs := launchSpecsFromJournal{st: rs, environ: func() []string { return env }}
	spec, err := specs.Lookup(ctx, "cursor", "gh")
	if err != nil {
		t.Fatal(err)
	}
	if spec.VServer != "vs-gh" || spec.ServerID != "gh" || spec.Command != f.childCmd {
		t.Fatalf("launch spec vserver=%q server=%q command=%q (env omitted)", spec.VServer, spec.ServerID, spec.Command)
	}
	if _, err := specs.Lookup(ctx, "cursor", "slack"); !errors.Is(err, record.ErrNotFound) {
		t.Fatalf("an unbound entry must have no launch spec: %v", err)
	}

	// The relay exactly as `observer mcp-relay wrap` builds it (node-local
	// mediation, no token client), over the SAME journal/record DB.
	logger := slog.New(slog.DiscardHandler)
	rt, err := buildMCPRelay(ctx, cfg, database, nil, h, logger, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := rt.relay.ServeStdioWrapper(ctx, mcprelay.WrapperOptions{Spec: spec, Stdin: inR, Stdout: outW, Stderr: io.Discard, ExitGrace: 3 * time.Second})
		_ = outW.Close()
		done <- err
	}()
	fr := mcprelay.NewFrameReader(outR, 0)
	recv := func() *mcprelay.Message {
		t.Helper()
		type res struct {
			b   []byte
			err error
		}
		ch := make(chan res, 1)
		go func() { b, err := fr.Next(); ch <- res{b, err} }()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("read: %v", r.err)
			}
			m, err := mcprelay.ParseMessage(r.b)
			if err != nil {
				t.Fatal(err)
			}
			return m
		case <-time.After(20 * time.Second):
			t.Fatal("no frame from the wrapper")
		}
		return nil
	}
	send := func(frame string) {
		if err := mcprelay.WriteFrame(inW, []byte(frame)); err != nil {
			t.Fatal(err)
		}
	}

	// Permitted: allow grant g-allow on vs-gh -> the CHILD answers.
	send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"title":"t"}}}`)
	m := recv()
	if m.Error != nil || !strings.Contains(string(m.Result), "child:create_issue") || string(m.ID) != "1" {
		t.Fatalf("permitted call did not round-trip through the child: id=%s result=%s err=%+v", m.ID, m.Result, m.Error)
	}
	// Denied: deny grant g-deny -> refused by the relay, never forwarded.
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`)
	m = recv()
	if m.Error == nil || string(m.ID) != "2" || strings.Contains(string(m.Result), "child:") {
		t.Fatalf("denied call was not refused: id=%s result=%s err=%+v", m.ID, m.Result, m.Error)
	}
	_ = inW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrapper exit: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("wrapper did not exit after the client closed its stream")
	}
	logged, _ := os.ReadFile(f.childLog)
	if !strings.Contains(string(logged), "create_issue") {
		t.Fatalf("the child never received the permitted call:\n%s", logged)
	}
	if strings.Contains(string(logged), "delete_repo") {
		t.Fatalf("a denied call reached the child:\n%s", logged)
	}
	if head, err := rs.Head(ctx); err != nil || head.Seq == 0 {
		t.Fatalf("no decision recorded in the relay chain: %+v %v", head, err)
	}
}

// TestMCPRelay_CoverageAndACKFollowVerifiedApplied is finding 3 through the
// production derivation (mcpRelayAppliedState -> coverage.Live + the relay
// point's projection.applied capability): a stage+journal that never lands
// its commit is NOT applied (matrix and ACK honest); a stdio-only
// projection with a token client later wired never makes remote mediated;
// a config edited after the projection stops claiming it on the live ACK.
func TestMCPRelay_CoverageAndACKFollowVerifiedApplied(t *testing.T) {
	ctx := context.Background()
	f := newMCPRelayWrapFixture(t)
	cfg := mcpRelayTestCfg(t, true)
	cfg.MCPRelay.Listen = "127.0.0.1:8859"
	database, err := dbtemplate.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	rs := record.NewSQLStore(database, "")
	h := appliedHandle(t, cfg, "enforce", false)
	h.SetProjectionProbe(func() bool { return mcpRelayAppliedState(context.Background(), rs).Any() })
	find := func(tr coverage.Transport) coverage.Coverage {
		for _, r := range coverage.Matrix(mcpRelayCoverageLive(ctx, cfg, rs, h, true)) {
			if r.Client == "cursor" && r.Transport == tr && r.Method == coverage.MethodCatalogue {
				return r.Coverage
			}
		}
		return ""
	}
	ackApplied := func() bool {
		_, missing := coverage.Status(coverage.PointRelay, h.pointCapabilities())
		for _, m := range missing {
			if m == "projection.applied" {
				return false
			}
		}
		return true
	}

	// 1. Stage + journal succeed, the commit fails: rows exist, the file is
	//    the original - NOT applied, on the matrix and on the ACK.
	registrar, exe, err := mcpRelayRegistrar()
	if err != nil {
		t.Fatal(err)
	}
	desired, _ := mcpRelayDesired(cfg, h, exe, "", false)
	p := &project.Projector{Writer: failingCommit{registrar}, Journal: newMCPRelayJournal(cfg, rs)}
	rep, err := p.Apply(ctx, registrar.RelayClients(), desired)
	if err != nil {
		t.Fatal(err)
	}
	var failed bool
	for _, r := range rep.Receipts {
		if r.Client.Tool == "cursor" && strings.Contains(r.Err, "commit:") {
			failed = true
		}
	}
	if rows, _ := rs.ListLaunchSpecs(ctx); !failed || len(rows) != 1 {
		t.Fatalf("expected a retained row after a failed commit: failed=%v rows=%+v", failed, rows)
	}
	if b, _ := os.ReadFile(f.cursorPath); !bytes.Equal(b, f.original) {
		t.Fatal("a failed commit changed the config")
	}
	if a := mcpRelayAppliedState(ctx, rs); a.Any() {
		t.Fatalf("a journal row whose commit failed counted as applied: %+v", a)
	}
	if c := find(coverage.TransportStdio); c == coverage.Mediated {
		t.Fatalf("stdio mediated by an unlanded write: %s", c)
	}
	if ackApplied() {
		t.Fatal("ACK claims projection.applied for an unlanded write")
	}
	if got := projectedClients(ctx, rs); len(got) != 0 {
		t.Fatalf("status lists an unlanded projection: %v", got)
	}

	// 2. The real apply lands (stdio only: remote forwarding was not wired
	//    at projection time). A token client wired LATER must not make the
	//    remote transport mediated - there is no remote row.
	if _, _, err := runMCPRelayProjection(ctx, cfg, "", rs, h, false); err != nil {
		t.Fatal(err)
	}
	a := mcpRelayAppliedState(ctx, rs)
	if !a.StdioApplied("cursor") || a.RemoteApplied("cursor") {
		t.Fatalf("applied state after a stdio-only apply: %+v", a)
	}
	if c := find(coverage.TransportRemoteHTTP); c == coverage.Mediated {
		t.Fatalf("stdio-only row + token client made remote mediated: %s", c)
	}
	if !ackApplied() {
		t.Fatal("ACK does not see the landed projection")
	}

	// 3. The operator edits the config after the projection: the live ACK
	//    probe (the SAME predicate) stops claiming it.
	b, _ := os.ReadFile(f.cursorPath)
	if err := os.WriteFile(f.cursorPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if ackApplied() || mcpRelayAppliedState(ctx, rs).Any() {
		t.Fatal("an edited config is still claimed as applied")
	}
}
