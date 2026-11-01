package agentconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

const schemaDir = "../../testdata/agentconfig/schemas"

func registryTools() map[string]bool {
	out := map[string]bool{}
	for _, t := range integration.Tools() {
		out[t] = true
	}
	return out
}

// TestBuildHasNoProblems: every overlay matches a row and no extra row
// shadows a generated one (an extra that the schema has since caught up
// with must be dropped, loudly).
func TestBuildHasNoProblems(t *testing.T) {
	for _, p := range buildProblems() {
		t.Error(p)
	}
}

var (
	knownTypes = map[ValueType]bool{
		TypeString: true, TypeEnum: true, TypeInt: true, TypeFloat: true, TypeBool: true,
		TypeStringList: true, TypeStringMap: true, TypeObject: true, TypeRuleList: true, TypeMCPMap: true,
	}
	knownVerified = map[Verified]bool{VerifiedDoc: true, VerifiedSchema: true, VerifiedLive: true, VerifiedUnverified: true}
	knownDanger   = map[DangerClass]bool{DangerNone: true, DangerConfirm: true, DangerRefuseWhileIntegrated: true}
	knownScope    = map[Scope]bool{ScopeManaged: true, ScopeSystem: true, ScopeUser: true, ScopeProjectShared: true, ScopeProjectLocal: true}
)

// TestCatalogRowsGrounded (plan section 2.2): every row is complete,
// grounded and consistent with the Files table and the registry.
func TestCatalogRowsGrounded(t *testing.T) {
	tools := registryTools()
	shapes := map[string]FileRow{}
	shapeScopes := map[string]map[Scope]bool{}
	userFiles := map[string]bool{}
	for _, f := range Files() {
		shapes[f.Shape] = f
		if f.WriteNeeds == PrivUser {
			userFiles[f.Shape+"\x00"+string(f.Scope)] = true
		}
		if shapeScopes[f.Shape] == nil {
			shapeScopes[f.Shape] = map[Scope]bool{}
		}
		shapeScopes[f.Shape][f.Scope] = true
	}
	rows := Catalog()
	if len(rows) < 1000 {
		t.Fatalf("catalogue has only %d rows", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		switch {
		case seen[r.ID]:
			t.Errorf("%s: duplicate id", r.ID)
		case r.ID != r.Tool+"/"+r.Path.String():
			t.Errorf("%s: id does not match tool + path %q", r.ID, r.Path.String())
		case !tools[r.Tool]:
			t.Errorf("%s: tool %q is not in the integration registry", r.ID, r.Tool)
		case r.Source == "":
			t.Errorf("%s: no Source", r.ID)
		case !knownTypes[r.Type]:
			t.Errorf("%s: unknown type %q", r.ID, r.Type)
		case !knownVerified[r.Verified]:
			t.Errorf("%s: unknown verified %q", r.ID, r.Verified)
		case !r.Owner.Known():
			t.Errorf("%s: unknown owner %q", r.ID, r.Owner)
		case !knownDanger[r.Danger]:
			t.Errorf("%s: unknown danger %q", r.ID, r.Danger)
		case r.Type == TypeEnum && len(r.Enum) == 0:
			t.Errorf("%s: enum row without values", r.ID)
		case r.Secret && r.Default != "":
			t.Errorf("%s: a secret row carries a default", r.ID)
		case r.Min != nil && r.Max != nil && *r.Min > *r.Max:
			t.Errorf("%s: min > max", r.ID)
		case len(r.Scopes) == 0:
			t.Errorf("%s: no scopes", r.ID)
		}
		seen[r.ID] = true
		f, ok := shapes[r.FileID]
		if !ok {
			t.Errorf("%s: file shape %q is not in the Files table", r.ID, r.FileID)
			continue
		}
		if f.Tool != r.Tool {
			t.Errorf("%s: file shape %q belongs to %s", r.ID, r.FileID, f.Tool)
		}
		for _, s := range r.Scopes {
			if !knownScope[s] {
				t.Errorf("%s: unknown scope %q", r.ID, s)
			} else if !shapeScopes[r.FileID][s] {
				t.Errorf("%s: scope %s has no file in shape %s", r.ID, s, r.FileID)
			}
		}
		// Every observer:<writer> row matches a whole-key owned span computed
		// from the registry (plan section 2.3), never a hand stamp.
		if r.Owner.IsObserver() && !ownedBySpan(r) {
			t.Errorf("%s: Observer owner %q matches no whole-key owned span", r.ID, r.Owner)
		}
		userWritable := false
		for _, s := range r.Scopes {
			userWritable = userWritable || userFiles[r.FileID+"\x00"+string(s)]
		}
		if r.Writable != (r.Owner == OwnerUser && userWritable) {
			t.Errorf("%s: Writable %v inconsistent with owner / file privilege", r.ID, r.Writable)
		}
	}
}

// TestOverlaysAndExtrasGrounded: every hand-written fact names its source,
// and an extra row is doc-grounded (a schema row would be generated).
func TestOverlaysAndExtrasGrounded(t *testing.T) {
	for _, tc := range toolCatalogs {
		if tc.VerifiedAgainst == "" {
			t.Errorf("%s: no VerifiedAgainst", tc.Tool)
		}
		if generatedRows[tc.Tool] == nil && len(tc.Overlays) > 0 {
			t.Errorf("%s: overlay without a generated row set (a doc-authored tool writes its rows as Extra)", tc.Tool)
		}
		if generatedRows[tc.Tool] == nil && len(tc.Extra) == 0 {
			t.Errorf("%s: a doc-authored catalogue with no rows", tc.Tool)
		}
		for _, f := range tc.Files {
			if f.Tool != tc.Tool {
				t.Errorf("%s: file row %s belongs to %s", tc.Tool, f.ID, f.Tool)
			}
		}
		for _, o := range tc.Overlays {
			if o.Source == "" {
				t.Errorf("overlay %s: no Source", o.ID)
			}
			if !strings.HasPrefix(o.ID, tc.Tool+"/") {
				t.Errorf("overlay %s: not a %s row", o.ID, tc.Tool)
			}
		}
		for _, x := range tc.Extra {
			if x.Source == "" || x.Verified == VerifiedSchema || x.Tool != tc.Tool {
				t.Errorf("extra %s: needs a Source, a non-schema Verified and Tool %s", x.ID, tc.Tool)
			}
		}
	}
}

var knownKinds = map[FileKind]bool{
	KindSettings: true, KindMCP: true, KindHooks: true, KindPermissions: true, KindInstructions: true,
	KindRule: true, KindSkill: true, KindAgent: true, KindCommand: true, KindToolState: true,
}

// TestEveryFileRowGrounded (plan section 2.1).
func TestEveryFileRowGrounded(t *testing.T) {
	tools := registryTools()
	seen := map[string]bool{}
	for _, f := range Files() {
		switch {
		case seen[f.ID]:
			t.Errorf("%s: duplicate id", f.ID)
		case !tools[f.Tool]:
			t.Errorf("%s: tool %q not in the registry", f.ID, f.Tool)
		case !strings.HasPrefix(f.ID, f.Tool+"/"):
			t.Errorf("%s: id does not start with the tool", f.ID)
		case !knownKinds[f.Kind]:
			t.Errorf("%s: unknown kind %q", f.ID, f.Kind)
		case !knownScope[f.Scope]:
			t.Errorf("%s: unknown scope %q", f.ID, f.Scope)
		case len(f.Paths.All()) == 0:
			t.Errorf("%s: no path on any OS", f.ID)
		case f.Shape == "":
			t.Errorf("%s: no shape", f.ID)
		case f.Grounding.Source == "" || f.Grounding.Kind == "":
			t.Errorf("%s: ungrounded", f.ID)
		case f.WriteNeeds != PrivUser && f.WriteNeeds != PrivAdminRoot && f.WriteNeeds != PrivNever:
			t.Errorf("%s: unknown privilege %q", f.ID, f.WriteNeeds)
		case f.Gitignored && f.Scope != ScopeProjectLocal:
			t.Errorf("%s: only a project_local file can be gitignored", f.ID)
		case f.Kind == KindToolState && f.WriteNeeds != PrivNever:
			t.Errorf("%s: tool state must never be written", f.ID)
		}
		seen[f.ID] = true
		if _, ok := f.Format.Engine(); !ok && f.Format != FormatCrushrc && f.Format != FormatScript {
			t.Errorf("%s: format %q has no engine", f.ID, f.Format)
		}
		if f.Scope == ScopeManaged && f.WriteNeeds == PrivUser {
			t.Errorf("%s: a managed file writable by the user is lever B, declare it admin_root with a note", f.ID)
		}
	}
	// Every generated shape has at least one user-scope file, and its
	// files name the schema.
	for _, p := range SchemaPins() {
		user := false
		for _, f := range Files() {
			if f.Shape != p.Shape {
				continue
			}
			if f.SchemaURL == "" {
				t.Errorf("%s: shape %s is schema-generated but the file names no schema", f.ID, p.Shape)
			}
			user = user || f.Scope == ScopeUser
		}
		if !user {
			t.Errorf("shape %s has no user-scope file", p.Shape)
		}
	}
}

// TestEveryToolHasRowsOrHonestZero: every registry tool is exactly one of
// generated / authored (P2) / pending / no surface, with a note for the
// last two.
func TestEveryToolHasRowsOrHonestZero(t *testing.T) {
	tools := registryTools()
	for tool := range pendingTools {
		if !tools[tool] {
			t.Errorf("pendingTools names %q, which is not in the registry", tool)
		}
	}
	for tool := range noSurfaceTools {
		if !tools[tool] {
			t.Errorf("noSurfaceTools names %q, which is not in the registry", tool)
		}
	}
	authored := map[string]bool{}
	for _, tc := range toolCatalogs {
		if generatedRows[tc.Tool] == nil {
			authored[tc.Tool] = true
		}
	}
	for _, c := range Coverage() {
		n := 0
		for _, in := range []bool{generatedRows[c.Tool] != nil, authored[c.Tool], pendingTools[c.Tool] != "", noSurfaceTools[c.Tool] != ""} {
			if in {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s is in %d coverage categories, want exactly 1 (drop a pendingTools note once the tool is authored)", c.Tool, n)
		}
		switch c.Status {
		case CoverageGenerated, CoverageAuthored:
			if c.Rows == 0 || c.VerifiedAgainst == "" {
				t.Errorf("%s: %s with %d rows, verified against %q", c.Tool, c.Status, c.Rows, c.VerifiedAgainst)
			}
		default:
			if c.Note == "" || c.Rows != 0 {
				t.Errorf("%s: %s needs a note and zero rows (got %d)", c.Tool, c.Status, c.Rows)
			}
		}
	}
	if got := len(Coverage()); got != len(tools) {
		t.Fatalf("coverage reports %d tools, registry has %d", got, len(tools))
	}
}

// TestSchemaPinsMatchFiles: the generated rows came from the pinned bytes
// (a refreshed schema without a regeneration fails here even when the
// drift gate is not run).
func TestSchemaPinsMatchFiles(t *testing.T) {
	if len(SchemaPins()) != 8 {
		t.Fatalf("want the 8 schema-generated tools, got %d pins", len(SchemaPins()))
	}
	for _, p := range SchemaPins() {
		b, err := os.ReadFile(filepath.Join(schemaDir, p.File))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != p.SHA256 {
			t.Errorf("%s: %s changed since generation; run make agentconfig-catalog-build", p.Tool, p.File)
		}
	}
}

// secretShape matches credential VALUES (not names): vendor key prefixes,
// JWTs, PEM private keys.
var secretShape = regexp.MustCompile(`(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[bpas]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})`)

// TestNoSecretsAnywhere: the operator ruling that secrets never appear in
// plain text in the catalogue, the pinned schemas or the fixtures.
func TestNoSecretsAnywhere(t *testing.T) {
	for _, r := range Catalog() {
		for _, s := range []string{r.Default, r.Desc, r.Note, strings.Join(r.Enum, " ")} {
			if m := secretShape.FindString(s); m != "" {
				t.Errorf("%s carries a secret-shaped value %q", r.ID, m)
			}
		}
	}
	for _, dir := range []string{schemaDir, "../../testdata/cfgfmt"} {
		err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			if strings.Contains(strings.ToLower(p), "kimi") {
				t.Errorf("%s: no Kimi Code config may be copied into testdata", p)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if m := secretShape.Find(b); m != nil {
				t.Errorf("%s carries a secret-shaped value %q", p, m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// No Files row may point a writer at Kimi Code's key-bearing config.
	for _, f := range Files() {
		for _, p := range f.Paths.All() {
			if strings.Contains(p, ".kimi-code/config.toml") && f.WriteNeeds != PrivNever {
				t.Errorf("%s: ~/.kimi-code/config.toml holds a plaintext key; it must be PrivNever", f.ID)
			}
		}
	}
}

// TestCatalogLookups pins representative rows from each population tier.
func TestCatalogLookups(t *testing.T) {
	get := func(id string) SettingRow {
		t.Helper()
		r, ok := Setting(id)
		if !ok {
			t.Fatalf("missing row %s", id)
		}
		return r
	}
	if r := get("codex/model"); r.Type != TypeString || !r.Writable || r.Verified != VerifiedSchema {
		t.Errorf("codex/model = %+v", r)
	}
	if r := get("claude-code/permissions.defaultMode"); r.Danger != DangerConfirm || !contains(r.Enum, "bypassPermissions") {
		t.Errorf("defaultMode = %+v", r)
	}
	if r := get("claude-code/permissions.allow"); r.Type != TypeRuleList {
		t.Errorf("permissions.allow type = %s", r.Type)
	}
	if r := get("claude-code/env.ANTHROPIC_API_KEY"); !r.Secret || r.Default != "" {
		t.Errorf("ANTHROPIC_API_KEY = %+v", r)
	}
	if r := get("claude-code/env.AWS_BEARER_TOKEN_BEDROCK"); !r.Secret {
		t.Error("AWS_BEARER_TOKEN_BEDROCK must be secret")
	}
	if r := get("claude-code/disableAllHooks"); r.Danger != DangerRefuseWhileIntegrated {
		t.Errorf("disableAllHooks danger = %q", r.Danger)
	}
	if r := get("claude-code/allowManagedHooksOnly"); len(r.Scopes) != 1 || r.Scopes[0] != ScopeManaged || r.Writable {
		t.Errorf("allowManagedHooksOnly = scopes %v writable %v", r.Scopes, r.Writable)
	}
	if r := get("claude-code/maxEffortLevel"); r.Verified != VerifiedDoc {
		t.Errorf("extra row maxEffortLevel = %+v", r)
	}
	if r := get("codex/notify"); contains(scopeStrings(r.Scopes), string(ScopeProjectShared)) {
		t.Errorf("codex/notify must not be settable from a project file: %v", r.Scopes)
	}
	oi, cx := get("open-interpreter/approval_policy"), get("codex/approval_policy")
	if !contains(oi.Enum, "untrusted") || contains(cx.Enum, "untrusted") {
		t.Errorf("approval_policy enums: oi=%v codex=%v", oi.Enum, cx.Enum)
	}
	if r := get("gemini-cli/admin.secureModeEnabled"); len(r.Scopes) != 1 || r.Scopes[0] != ScopeManaged {
		t.Errorf("gemini admin scopes = %v", r.Scopes)
	}
	if r := get("opencode/mcp"); r.Type != TypeMCPMap {
		t.Errorf("opencode/mcp type = %s", r.Type)
	}
	if r := get("kilo-code-cli/snapshot"); r.Danger != DangerConfirm {
		t.Errorf("kilo snapshot danger = %q", r.Danger)
	}
	if _, ok := Setting("opencode/snapshot.nope"); ok {
		t.Error("lookup of a missing id succeeded")
	}
	if n := len(SettingsFor("crush")); n < 30 {
		t.Errorf("crush rows = %d", n)
	}
	// Returned rows are copies.
	a := get("codex/approval_policy")
	a.Enum[0] = "mutated"
	if b := get("codex/approval_policy"); b.Enum[0] == "mutated" {
		t.Error("Setting returned shared state")
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func scopeStrings(ss []Scope) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

// TestCoverageGolden pins the catalogue's coverage by status (phase P2
// closed the pending set): a change is deliberate and updates this table.
func TestCoverageGolden(t *testing.T) {
	got := map[CoverageStatus]int{}
	rows := 0
	for _, c := range Coverage() {
		got[c.Status]++
		rows += c.Rows
		t.Logf("%-17s %-10s rows=%4d verified=%4d writable=%4d secret=%3d dangerous=%3d", c.Tool, c.Status, c.Rows, c.Verified, c.Writable, c.Secret, c.Dangerous)
	}
	want := map[CoverageStatus]int{CoverageGenerated: 8, CoverageAuthored: 41, CoverageNoSurface: 6}
	for s, n := range want {
		if got[s] != n {
			t.Errorf("%s: %d tools, want %d", s, got[s], n)
		}
	}
	// The 2026-10-21 capture-only wave (ten tools) joined the registry
	// without a catalogue; surface-gap lane w4-catalog authored all ten.
	if got[CoveragePending] != 0 {
		t.Errorf("%d tools pending, want 0", got[CoveragePending])
	}
	t.Logf("total rows %d, map rows %d, owned spans %d", rows, len(MapRows()), len(OwnedSpans()))
}

// TestLocalOverlaysAreNeverTracked: a project file named "*.local.*" is a
// per-developer overlay its vendor keeps out of git, so it must be
// project_local and IsTracked must be false for it; the UI's "commits with
// the repo" warning reads IsTracked.
func TestLocalOverlaysAreNeverTracked(t *testing.T) {
	var sawClaudeLocal bool
	for _, r := range Files() {
		p := r.Paths.Linux
		if !strings.HasPrefix(p, "<project>/") || !strings.Contains(path.Base(p), ".local.") {
			continue
		}
		if r.Scope != ScopeProjectLocal || IsTracked(r) {
			t.Errorf("%s (%s): scope %s tracked=%v, want project_local and untracked", r.ID, p, r.Scope, IsTracked(r))
		}
		if p == "<project>/CLAUDE.local.md" {
			sawClaudeLocal = r.Gitignored
		}
	}
	if !sawClaudeLocal {
		t.Fatal("claude-code CLAUDE.local.md must be a gitignored project_local row")
	}
}
