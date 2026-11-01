//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecurityShareFor: the individual key decides an individual node, the
// in-force pull a managed one (posture by default), and org_key only rides
// a managed pull that carries the dedupe key at the findings level.
func TestSecurityShareFor(t *testing.T) {
	// Since lane LEFT-SHARED the node holds the key only when the pull
	// served it (org_dedupe), not when it only names one.
	served := &orgcontract.SecurityOrgDedupe{Version: 1, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	findingsKey := &orgcontract.SecurityManagedPolicyV1{Version: 1, FindingShare: "findings", OrgDedupeKey: "acme-dedupe-2026", OrgDedupe: served}
	cases := []struct {
		name    string
		managed bool
		pull    *orgcontract.SecurityManagedPolicyV1
		local   string
		want    store.SecurityShare
	}{
		{"individual default", false, nil, "", store.SecurityShare{Level: "off"}},
		{"individual findings", false, nil, "findings", store.SecurityShare{Level: "findings"}},
		{"individual ignores a pull", false, findingsKey, "", store.SecurityShare{Level: "off"}},
		{"managed no pull", true, nil, "off", store.SecurityShare{Level: "posture"}},
		{"managed pull with key", true, findingsKey, "", store.SecurityShare{Level: "findings", HoldsOrgKey: true}},
		{"managed pull without key", true, &orgcontract.SecurityManagedPolicyV1{Version: 1, FindingShare: "findings"}, "", store.SecurityShare{Level: "findings"}},
		{"managed pull naming a key it did not serve", true, &orgcontract.SecurityManagedPolicyV1{Version: 1, FindingShare: "findings", OrgDedupeKey: "acme"}, "", store.SecurityShare{Level: "findings"}},
	}
	for _, c := range cases {
		if got := securityShareFor(c.managed, c.pull, c.local); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestBindSecurityOrgProvidersOnlyWhileActive: with the module inactive the
// seam is unbound and the push composes no security row (byte-identical);
// active, an individual node at the default level still sends none, and at
// findings it sends the rows.
func TestBindSecurityOrgProvidersOnlyWhileActive(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `INSERT INTO sec_findings (id, project_root_hash, local_key, rule_id, category, severity, confidence, first_seen, last_seen, rel_path)
		VALUES ('f1', 'r1', 'k1', 'S-721', 'secret', 'high', 'high', ?, ?, 'a.go')`, now, now); err != nil {
		t.Fatal(err)
	}
	push := func(share store.ShareOptions) store.PushBatch {
		t.Helper()
		b, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org", "dev@x", share, store.ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	bindSecurityOrgProviders(st, false)
	if b := push(store.ShareOptions{Security: "findings"}); b.SecurityFindings != nil || b.SecurityPosture != nil {
		t.Fatalf("an inactive module composed security rows")
	}
	bindSecurityOrgProviders(st, true)
	if b := push(store.ShareOptions{}); b.SecurityFindings != nil || b.SecurityPosture != nil {
		t.Fatalf("an individual node at the default level composed security rows")
	}
	b := push(store.ShareOptions{Security: "findings"})
	if len(b.SecurityFindings) != 1 || len(b.SecurityPosture) != 1 {
		t.Fatalf("findings level: %d findings, %d posture rows", len(b.SecurityFindings), len(b.SecurityPosture))
	}
	if b.SecurityFindings[0].RelPath != "" {
		t.Errorf("metadata-only push carried a path")
	}
}

// TestSecurityPostureNodeFacts: the daemon's facts land as closed enums,
// with the E1 floor evaluation (an individual node reports managed-only
// keys not_applicable).
func TestSecurityPostureNodeFacts(t *testing.T) {
	spec, _, err := securityscanning.CompileBody([]byte(`{"version":1,"require":{"commit_gate":"quick_scan"}}`), 1<<16)
	if err != nil {
		t.Fatalf("CompileBody: %v", err)
	}
	facts := securityscanning.NodeFacts{Active: map[string]bool{"security.secrets": true}, Held: &spec}
	var row orgcontract.SecurityPostureRow
	securityPostureNodeFacts(&row, facts, false)
	if strings.Join(row.Detectors, ",") != "security,security.secrets" || row.OnlineChecks != "off" {
		t.Errorf("facts: %+v", row)
	}
	if len(row.FloorKeys) == 0 {
		t.Fatalf("no floor keys reported")
	}
	for _, k := range row.FloorKeys {
		if k.State == "" {
			t.Errorf("floor key without a state: %+v", k)
		}
	}
	off := securityscanning.NodeFacts{ModuleOff: true, Active: map[string]bool{"security.secrets": true}}
	row = orgcontract.SecurityPostureRow{}
	securityPostureNodeFacts(&row, off, true)
	if len(row.Detectors) != 0 || row.OnlineChecks != "on" {
		t.Errorf("module off: %+v", row)
	}
}

// TestSecurityManagedKeyLinesShare: the E1 pull rows finding_share and
// org_dedupe_key are built now (lane SEC-E2).
func TestSecurityManagedKeyLinesShare(t *testing.T) {
	p := &orgcontract.SecurityManagedPolicyV1{Version: 1, FindingShare: "findings", OrgDedupeKey: "acme"}
	lines := strings.Join(securityManagedKeyLines(p, false, func(string) bool { return true }), "\n")
	for _, want := range []string{"finding_share = findings: applied", "org_dedupe_key = acme: applied"} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in:\n%s", want, lines)
		}
	}
	if strings.Contains(lines, "finding_share = findings: not_applicable") {
		t.Errorf("finding_share still reported not built")
	}
	p.FindingShare = "posture"
	lines = strings.Join(securityManagedKeyLines(p, false, func(string) bool { return true }), "\n")
	if !strings.Contains(lines, "org_dedupe_key = acme: not_applicable: finding_share is not findings") {
		t.Errorf("posture level: %s", lines)
	}
}

// TestStartBindsSecurityOrgSeamWithThePushLoop pins lane SEC-E2 audit
// finding 3: the daemon binds the security wire seam where it builds the
// org push loop (the block that takes the bundle's store), never inside the
// dashboard branch, so `--no-dashboard` and a dashboard-inactive managed node
// send their rows and the status line's "posture" is the truth.
func TestStartBindsSecurityOrgSeamWithThePushLoop(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "start.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	render := func(n ast.Node) string {
		var b bytes.Buffer
		_ = printer.Fprint(&b, fset, n)
		return b.String()
	}
	calls := 0
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "bindSecurityOrgProviders" {
			return true
		}
		calls++
		for _, a := range stack {
			if ifs, ok := a.(*ast.IfStmt); ok && strings.Contains(render(ifs.Cond), "noDashboard") {
				t.Errorf("%s: bindSecurityOrgProviders sits under `if %s`; a headless daemon would never bind it", fset.Position(call.Pos()), render(ifs.Cond))
			}
		}
		var block *ast.BlockStmt
		for i := len(stack) - 1; i >= 0 && block == nil; i-- {
			block, _ = stack[i].(*ast.BlockStmt)
		}
		if block == nil || !strings.Contains(render(block), "orgStore = bundle.client, bundle.store") {
			t.Errorf("%s: bindSecurityOrgProviders is not bound where the push loop takes the bundle's store", fset.Position(call.Pos()))
		}
		return true
	})
	if calls != 1 {
		t.Fatalf("start.go calls bindSecurityOrgProviders %d times, want exactly once", calls)
	}
}

// withSecurityNodeState installs the daemon's tenancy base and in-force
// managed pull for one test, restoring both after.
func withSecurityNodeState(t *testing.T, managed bool, pull *orgcontract.SecurityManagedPolicyV1) {
	t.Helper()
	secScanning.mu.Lock()
	load, base, ok, at := secScanning.load, secScanning.base, secScanning.baseOK, secScanning.loadedAt
	secScanning.load, secScanning.base, secScanning.baseOK, secScanning.loadedAt = nil, securityScanningBase{Managed: managed, Security: config.DefaultSecurityConfig()}, true, time.Now()
	secScanning.mu.Unlock()
	secManaged.mu.Lock()
	cur := secManaged.cur
	secManaged.cur = securityManagedState{Policy: pull}
	secManaged.mu.Unlock()
	t.Cleanup(func() {
		secScanning.mu.Lock()
		secScanning.load, secScanning.base, secScanning.baseOK, secScanning.loadedAt = load, base, ok, at
		secScanning.mu.Unlock()
		secManaged.mu.Lock()
		secManaged.cur = cur
		secManaged.mu.Unlock()
	})
}

// TestSecurityWireRealCmdShareResolution (lane SEC-E2 audit finding 9)
// drives the REAL cmd-layer share resolution end to end through the push
// composer: the daemon's binding (securityShareFor over secScanning.baseNow
// and securityManagedCurrent), not a test-bound Level func. An individual
// node follows its own key; a managed node sends posture by default and
// full rows with org_key under a pull that sets findings with the key.
func TestSecurityWireRealCmdShareResolution(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `INSERT INTO sec_findings (id, project_root_hash, local_key, org_key, rule_id, category, severity, confidence, first_seen, last_seen, rel_path)
		VALUES ('f1', 'r1', 'k1', ?, 'S-721', 'secret', 'high', 'high', ?, ?, 'a.go')`, "v1:"+strings.Repeat("e", 64), now, now); err != nil {
		t.Fatal(err)
	}
	// The stored org_key is version-tagged (lane LEFT-SHARED); it ships as
	// the bare digest while the pull serves that key version.
	servedKey := &orgcontract.SecurityOrgDedupe{Version: 1, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	withKey := &orgcontract.SecurityManagedPolicyV1{Version: 1, FindingShare: "findings", OrgDedupeKey: "acme-dedupe", OrgDedupe: servedKey}
	cases := []struct {
		name         string
		managed      bool
		pull         *orgcontract.SecurityManagedPolicyV1
		share        store.ShareOptions
		wantPosture  bool
		wantFindings bool
		wantPath     bool
		wantOrgKey   bool
	}{
		{"individual default", false, nil, store.ShareOptions{FullContent: true}, false, false, false, false},
		{"individual ignores a pull", false, withKey, store.ShareOptions{FullContent: true}, false, false, false, false},
		{"individual findings, metadata only", false, nil, store.ShareOptions{Security: "findings"}, true, true, false, false},
		{"managed default posture", true, nil, store.ShareOptions{EnterpriseGranted: true, Security: "off"}, true, false, false, false},
		{"managed pull findings with key", true, withKey, store.ShareOptions{EnterpriseGranted: true}, true, true, true, true},
	}
	for _, c := range cases {
		withSecurityNodeState(t, c.managed, c.pull)
		st := store.New(database)
		bindSecurityOrgProviders(st, true)
		b, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org", "dev@x", c.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(b.SecurityPosture) == 1; got != c.wantPosture {
			t.Errorf("%s: posture %v, want %v", c.name, got, c.wantPosture)
		}
		if got := len(b.SecurityFindings) == 1; got != c.wantFindings {
			t.Fatalf("%s: %d findings, want one=%v", c.name, len(b.SecurityFindings), c.wantFindings)
		}
		if !c.wantFindings {
			continue
		}
		f := b.SecurityFindings[0]
		if (f.RelPath != "") != c.wantPath || (f.OrgKey != "") != c.wantOrgKey {
			t.Errorf("%s: path %q org_key %q, want path=%v key=%v", c.name, f.RelPath, f.OrgKey, c.wantPath, c.wantOrgKey)
		}
	}
}
