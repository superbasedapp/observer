package integration_test

import (
	"context"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformast"
)

// TestRegistryCoversEveryRegisteredAdapter pins that every adapter in the
// canonical defaults.Adapters() list has an integration.Capability row.
// This is the guardrail the new-adapter checklist relies on: add an adapter
// without a registry row and this test goes red, forcing the capability
// declaration that init/register/MCP/doctor iterate. Lives in an external
// test package so it can import adapterdefaults without coupling the pure
// integration package to it.
func TestRegistryCoversEveryRegisteredAdapter(t *testing.T) {
	for _, a := range adapterdefaults.Adapters() {
		name := a.Name()
		if _, ok := integration.For(name); !ok {
			t.Errorf("adapter %q has no integration.Capability row — add one in internal/integration", name)
		}
	}
}

// TestRegistryHasNoOrphanRows pins the reverse: every registry row maps to a
// registered adapter (no stale rows for removed adapters).
//
// A multi-phase adapter build may temporarily land a registry row ahead of
// its parser package + defaults.Adapters() entry; the sanctioned way to do
// that is a documented, dated exception map here that is DELETED the moment
// the package lands. The 2026-07-29 wave (droid / open-interpreter /
// command-code) used one and it was retired when those three registered —
// so this test currently guards the general case with no exceptions, which
// is the state it should normally be in.
func TestRegistryHasNoOrphanRows(t *testing.T) {
	registered := map[string]bool{}
	for _, a := range adapterdefaults.Adapters() {
		registered[a.Name()] = true
	}
	for _, c := range integration.Capabilities() {
		if !registered[c.Tool] {
			t.Errorf("registry row %q has no registered adapter — remove the stale row", c.Tool)
		}
	}
}

// registryRowlessTaxonomyTools is the FROZEN, acknowledged set of tool ids
// that internal/tooltax carries tool-specific vocabulary rows for while
// internal/integration deliberately carries NO capability row. The value is
// the grounded reason the asymmetry is correct, not a TODO.
//
// Why the set is not simply empty: a registry row is keyed on ADAPTER
// IDENTITY, not on the `sessions.tool` value a row can end up tagged with.
// The registry's own contract says so from both sides —
// TestRegistryCoversEveryRegisteredAdapter (every defaults.Adapters() entry
// needs a row) plus TestRegistryHasNoOrphanRows (every row needs a
// defaults.Adapters() entry), and tests/invariant/adapter_registry_sync_test.go
// pins the same set equality a third time. tooltax, by contrast, is keyed on
// the emitted `tool` COLUMN, because that is what Resolve(tool, native) is
// handed at read time. The two key spaces differ by exactly the adapters that
// retag their events per-file, and this map is where that difference is
// declared out loud.
//
// The teeth: a FUTURE tooltax alias (internal/tooltax/table.go::toolAliases)
// or any new tool-specific tooltax vocabulary that silently lacks a registry
// row now fails here instead of being discovered in a prose note.
var registryRowlessTaxonomyTools = map[string]string{
	"roo-code": "roo-code has no adapter identity: internal/adapter/cline.Adapter " +
		"watches BOTH saoudrizwan.claude-dev/tasks and rooveterinaryinc.roo-cline/tasks " +
		"and picks the emitted Tool per-FILE from the enclosing extension dir " +
		"(adapter.go toolFromPath), while its Name() is models.ToolCline. There is no " +
		"roo-code entry in defaults.Adapters(), no roo-code hook registrar, no roo-code " +
		"MCP registrar and no roo-code proxy route or launcher — so every cell of a " +
		"roo-code Capability would either be zero or be copied from cline's row, which " +
		"the registry's honesty rule forbids (a zero value means \"no grounded " +
		"capability\", never an inferred one). Contrast kilo-code, which DOES have a row " +
		"because kilocode.NewLegacy() is a registered adapter with its own Name() and " +
		"its own watch roots even though it wraps the same cline parser.",
	"zoo-code": "zoo-code (ZooCode, ZooCodeOrganization.zoo-code — the community " +
		"continuation of Roo Code after its 2026-04-21 shutdown) has the exact same " +
		"shape of no-adapter-identity as roo-code, added 2026-09-03 (uncaptured-" +
		"surfaces wiring plan, ticket U1): it is a row in the SAME clineExtensions " +
		"table roo-code lives in (internal/adapter/cline/roots.go), retagged per-file " +
		"by internal/adapter/cline.Adapter, whose own Name() stays models.ToolCline. " +
		"There is no zoo-code entry in defaults.Adapters(), no zoo-code hook " +
		"registrar, no zoo-code MCP registrar and no zoo-code proxy route or " +
		"launcher — so every cell of a zoo-code Capability would either be zero or " +
		"be copied from cline's row, which the registry's honesty rule forbids.",
}

// TestRegistryRowlessTaxonomyToolsAreFrozen makes the tooltax-vs-registry key-
// space asymmetry STRUCTURAL rather than a prose note in the taxonomy plan
// (docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §6 WP-T3).
//
// It is the mirror image of TestVocabularyDeclaredForEveryAdapter: that test
// walks registry rows and demands each declare its tooltax coverage; this one
// walks tooltax tools and demands each either HAVE a registry row or be an
// acknowledged, reasoned exception. Together the two directions close the set.
//
// Both staleness directions are checked, so the exception map cannot rot:
// an entry naming a tool tooltax no longer carries, or an entry for a tool
// that has since GAINED a registry row, both fail and must be deleted.
func TestRegistryRowlessTaxonomyToolsAreFrozen(t *testing.T) {
	taxonomyTools := map[string]bool{}
	for _, tool := range tooltax.Tools() {
		taxonomyTools[tool] = true
	}
	if len(taxonomyTools) < 20 {
		t.Fatalf("only %d tool-specific tooltax tools — the taxonomy table shape probably changed", len(taxonomyTools))
	}

	// Direction 1: every tooltax tool without a registry row must be a
	// declared, reasoned exception.
	for tool := range taxonomyTools {
		if _, ok := integration.For(tool); ok {
			continue
		}
		reason, acknowledged := registryRowlessTaxonomyTools[tool]
		if !acknowledged {
			t.Errorf("tool %q has tool-specific rows in internal/tooltax but no "+
				"integration.Capability row. Either add the registry row (the normal "+
				"answer: a new adapter lands in defaults.Adapters() + the registry + "+
				"config.Default().EnabledAdapters together), or — if the tool is an "+
				"event-level retag with no adapter identity — add it to "+
				"registryRowlessTaxonomyTools with the grounded reason.", tool)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("registryRowlessTaxonomyTools[%q] has an empty reason — an "+
				"acknowledged asymmetry must say WHY no row can be grounded", tool)
		}
	}

	// Direction 2: no stale exceptions.
	registeredAdapters := map[string]bool{}
	for _, a := range adapterdefaults.Adapters() {
		registeredAdapters[a.Name()] = true
	}
	for tool := range registryRowlessTaxonomyTools {
		if !taxonomyTools[tool] {
			t.Errorf("registryRowlessTaxonomyTools names %q, which internal/tooltax no "+
				"longer carries tool-specific rows for — delete the stale exception", tool)
		}
		if _, ok := integration.For(tool); ok {
			t.Errorf("registryRowlessTaxonomyTools names %q, which now HAS an "+
				"integration.Capability row — delete the stale exception", tool)
		}
		if registeredAdapters[tool] {
			t.Errorf("registryRowlessTaxonomyTools names %q, which is now a registered "+
				"adapter in defaults.Adapters() — it has an adapter identity, so it "+
				"needs a registry row; delete the exception", tool)
		}
	}
}

// TestRegistryRowlessTaxonomyToolsAreServedByAnotherAdapter grounds the
// exception map's central claim — "no adapter identity, but the sessions
// ARE captured" — against the code rather than the comment. A tool listed
// here must be reachable as an emitted `tool` value from some registered
// adapter's parser; if nothing in the tree can ever emit it, the tooltax
// rows are dead vocabulary and the honest fix is to delete THOSE, not to
// keep an exception alive.
//
// The check is deliberately narrow (a source scan of internal/adapter for
// the tool's models.Tool* constant, or the bare literal) because the emit
// is a per-file branch inside another adapter's parser, which no
// registry-shaped lookup can see.
func TestRegistryRowlessTaxonomyToolsAreServedByAnotherAdapter(t *testing.T) {
	for tool := range registryRowlessTaxonomyTools {
		found, where := emittedByAnAdapterPackage(t, tool)
		if !found {
			t.Errorf("registryRowlessTaxonomyTools names %q, but no adapter package "+
				"under internal/adapter emits it — the tooltax rows for %q are dead "+
				"vocabulary; delete them rather than keeping the exception", tool, tool)
			continue
		}
		t.Logf("%q emitted by %s (no adapter identity of its own)", tool, where)
	}
}

// modelsToolConstant returns the internal/models identifier whose value is
// the given tool id (e.g. "roo-code" -> "ToolRooCode"). Adapters emit the
// CONSTANT, never the literal, so a source scan has to know its name.
func modelsToolConstant(t *testing.T, tool string) string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, "../models", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing internal/models: %v", err)
	}
	want := strconv.Quote(tool)
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
						continue
					}
					lit, ok := vs.Values[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING || lit.Value != want {
						continue
					}
					return vs.Names[0].Name
				}
			}
		}
	}
	return ""
}

// emittedByAnAdapterPackage reports whether any non-test, build-selected
// file under internal/adapter references the tool's models.Tool* constant
// as an ACTUAL EXPRESSION IN EXECUTABLE CODE — the sole ground truth the
// codex review demanded, replacing the earlier raw substring scan (which a
// comment, a `var _ =` dead anchor, or a build-excluded file could satisfy
// without the tool ever actually being emitted).
//
// Three tightenings over the substring scan, all load-bearing:
//
//  1. Only the models.<Const> CONSTANT counts — never the bare string
//     literal — so a mutation that swaps `return models.ToolRooCode` for a
//     hardcoded string literal (leaving the constant name only in a
//     comment) is caught rather than passed on the literal's coincidental
//     presence.
//  2. The reference must sit in one of the executable-code sites the
//     finding named: a return statement, the RHS of an assignment or a
//     non-blank var declaration, a composite-literal element (keyed or
//     not), or a function-call argument — see validCodeSite. Because the
//     check walks the AST rather than scanning bytes, a comment can never
//     satisfy it (comments are not represented as expression nodes), and a
//     `var _ = models.ToolX` dead anchor is explicitly rejected even
//     though it is syntactically a var declaration's RHS.
//  3. Only files go/build.Context.MatchFile selects for the CURRENT
//     platform are scanned — a file gated out by a GOOS/GOARCH filename
//     suffix or an explicit `//go:build` / `// +build` constraint that
//     does not match this host is skipped exactly as `go build` would skip
//     it. (This does not evaluate custom `-tags`-gated constraints beyond
//     go/build's default context — none of internal/adapter's build tags
//     are custom today; only OS/arch selection is exercised in practice.)
func emittedByAnAdapterPackage(t *testing.T, tool string) (bool, string) {
	t.Helper()
	ident := modelsToolConstant(t, tool)
	if ident == "" {
		return false, ""
	}
	var hit string
	buildCtx := build.Default
	err := filepath.Walk("../adapter", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if hit != "" || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir, name := filepath.Split(path)
		if match, merr := buildCtx.MatchFile(dir, name); merr != nil || !match {
			// Unreadable, or excluded by build constraints for this
			// platform — `go build` would skip it too.
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		if modelsConstUsedAsCodeExpression(f, ident) {
			hit = filepath.ToSlash(path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/adapter: %v", err)
	}
	return hit != "", hit
}

// modelsConstUsedAsCodeExpression reports whether `models.<ident>` appears
// anywhere in file f as an expression sitting in one of the executable-code
// sites validCodeSite recognizes.
func modelsConstUsedAsCodeExpression(f *ast.File, ident string) bool {
	v := &modelsConstUseVisitor{ident: ident}
	ast.Walk(v, f)
	return v.found
}

// modelsConstUseVisitor walks a file's AST maintaining a stack of enclosing
// nodes, so it can classify whether a matching `models.<ident>` selector
// sits in a valid executable-code site rather than, say, a comment (never
// visited — comments are not AST expression nodes) or a dead declaration.
//
// It relies on go/ast's Walk contract: "if the result visitor w is not
// nil, Walk visits each of the children of node with the visitor w,
// followed by a call of w.Visit(nil)" — the nil call is what lets Visit
// pop the stack on the way back out, giving a correct parent at every
// point of the pre-order traversal.
type modelsConstUseVisitor struct {
	ident string
	stack []ast.Node
	found bool
}

func (v *modelsConstUseVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		if len(v.stack) > 0 {
			v.stack = v.stack[:len(v.stack)-1]
		}
		return nil
	}
	if !v.found && isModelsSelector(n, v.ident) && validCodeSite(v.stack, n) {
		v.found = true
	}
	v.stack = append(v.stack, n)
	return v
}

// isModelsSelector reports whether n is exactly the selector expression
// `models.<ident>`.
func isModelsSelector(n ast.Node, ident string) bool {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != ident {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	return ok && pkgIdent.Name == "models"
}

// validCodeSite reports whether n's immediate enclosing node (the top of
// stack) is one of the executable-code sites the finding requires: a
// return statement, the RHS of an assignment or a non-blank var
// declaration, a composite-literal element (keyed or not), or a
// function-call argument.
//
// A `var _ = models.ToolX` dead anchor is explicitly excluded — even
// though it is syntactically a ValueSpec whose Values contains n — by
// checking that at least one of the ValueSpec's Names is not the blank
// identifier.
func validCodeSite(stack []ast.Node, n ast.Node) bool {
	if len(stack) == 0 {
		return false
	}
	switch p := stack[len(stack)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.AssignStmt:
		for _, rhs := range p.Rhs {
			if rhs == n {
				return true
			}
		}
	case *ast.ValueSpec:
		allBlank := true
		for _, name := range p.Names {
			if name.Name != "_" {
				allBlank = false
				break
			}
		}
		if allBlank {
			// `var _ = models.ToolX` — a dead anchor, not an emission.
			return false
		}
		for _, val := range p.Values {
			if val == n {
				return true
			}
		}
	case *ast.KeyValueExpr:
		return p.Value == n
	case *ast.CompositeLit:
		for _, elt := range p.Elts {
			if elt == n {
				return true
			}
		}
	case *ast.CallExpr:
		for _, arg := range p.Args {
			if arg == n {
				return true
			}
		}
	}
	return false
}

// transcriptReader mirrors the handoffsvc TranscriptReader seam locally so
// this test can pin reader implementations without importing the boundary
// package.
type transcriptReader interface {
	ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error)
}

// TestHandoffClassifiedForEveryAdapter is the session-handoff sibling of
// the routability pin: every adapter's Handoff row must expose at least
// the universal file lane, and every adapter that SHIPS a transcript
// reader must be classified TranscriptFull (a reader on an actions-only
// row is a classification bug; a Full row without a reader is fine — the
// P2 tranche ships readers incrementally).
func TestHandoffClassifiedForEveryAdapter(t *testing.T) {
	for _, a := range adapterdefaults.Adapters() {
		cap, _ := integration.For(a.Name())
		if len(cap.Handoff.Lanes()) == 0 {
			t.Errorf("adapter %q: Handoff.Lanes() must include at least the file lane", a.Name())
		}
		if _, ok := a.(transcriptReader); ok && cap.Handoff.Transcript != integration.TranscriptFull {
			t.Errorf("adapter %q implements ReadTranscript but its Handoff row is %q, not full", a.Name(), cap.Handoff.Transcript)
		}
	}
}

// TestLaunchableImpliesInjectPrompt pins the launch capability's internal
// consistency: any adapter declaring a LaunchSpec (startable in the
// dashboard's embedded web terminal) must (a) name a launcher Subcommand
// and (b) also expose the InjectPrompt delivery lane — the launch path
// spawns `observer <Subcommand> --continue-from <id>`, which IS the
// inject_prompt lane, so a Launch row without InjectPrompt would be an
// incoherent capability. The cmd-side sync test
// (cmd/observer) pins Subcommand against the actual wired launcher.
func TestLaunchableImpliesInjectPrompt(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if !c.Handoff.Launchable() {
			continue
		}
		if c.Handoff.Launch.Subcommand == "" {
			t.Errorf("adapter %q: Launch set but Subcommand empty", c.Tool)
		}
		// A DocAssisted launcher opens the TUI + writes the doc (file lane);
		// it injects no prompt, so it needs only the universal InjectFile
		// lane. A Seeded launcher DOES inject the handover as the first
		// prompt, so it must declare the InjectPrompt lane.
		want := integration.InjectPrompt
		if c.Handoff.Launch.Mode == integration.LaunchDocAssisted {
			want = integration.InjectFile
		}
		hasLane := false
		for _, l := range c.Handoff.Lanes() {
			if l == want {
				hasLane = true
				break
			}
		}
		if !hasLane {
			t.Errorf("adapter %q: Launch (mode %d) set but Handoff lacks the %q lane", c.Tool, c.Handoff.Launch.Mode, want)
		}
	}
}

// TestAttachImpliesLauncher pins the session-attach capability's internal
// consistency: any adapter declaring an AttachSpec (its PTY can be handed
// to the daemon via `observer <Subcommand> --attach`) must (a) name a
// non-empty Subcommand and (b) be Launchable — an attach spec is only
// meaningful when a wired launcher exists to spawn the attachable PTY, and
// the launcher IS the Launch capability. It also pins that the attach
// Subcommand matches the launcher's Subcommand, so the two can never drift
// (the cmd-side sync test pins Subcommand against the actual wired
// launcher). An Attach row without a launcher would be an incoherent
// capability.
func TestAttachImpliesLauncher(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Attach == nil {
			continue
		}
		if c.Attach.Subcommand == "" {
			t.Errorf("adapter %q: Attach set but Subcommand empty", c.Tool)
		}
		if !c.Handoff.Launchable() {
			t.Errorf("adapter %q: Attach set but the tool is not Launchable (no wired launcher)", c.Tool)
			continue
		}
		if c.Attach.Subcommand != c.Handoff.Launch.Subcommand {
			t.Errorf("adapter %q: Attach.Subcommand %q != Launch.Subcommand %q (must name the same wired launcher)",
				c.Tool, c.Attach.Subcommand, c.Handoff.Launch.Subcommand)
		}
	}
}

// TestLaunchableImpliesAttach pins the attach-all-launchers invariant
// (2026-07-24): every row with a wired launcher (Handoff.Launch != nil) must
// ALSO declare an AttachSpec whose Subcommand equals the launcher's — because
// every `observer <verb>` launcher now attaches-by-default, so a launchable
// tool without a grounded Attach row would be a launcher the daemon refuses to
// spawn a PTY for (validateAttachCapability). Together with
// TestAttachImpliesLauncher (Attach ⇒ Launchable + verb equality) this makes
// Launch-grounded ⇔ Attach-grounded with equal verbs. Non-launcher rows
// (Handoff.Launch == nil — the *-web rows, legacy IDE adapters, aider, crush,
// cowork) are skipped: nothing to attach to.
func TestLaunchableImpliesAttach(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if !c.Handoff.Launchable() {
			continue
		}
		if c.Attach == nil {
			t.Errorf("adapter %q: Launchable but no AttachSpec — every `observer <verb>` launcher attaches by default; add Attach: &AttachSpec{Subcommand: %q}", c.Tool, c.Handoff.Launch.Subcommand)
			continue
		}
		if c.Attach.Subcommand != c.Handoff.Launch.Subcommand {
			t.Errorf("adapter %q: Attach.Subcommand %q != Launch.Subcommand %q (must name the same wired launcher)",
				c.Tool, c.Attach.Subcommand, c.Handoff.Launch.Subcommand)
		}
	}
}

// TestNativeResumeGrounded pins the native-resume grounding rule: any row
// declaring Resume.Kind == ResumeNative must name a non-empty Subcommand
// AND IDMechanism — native resume is declared only for a tool whose
// resume argv has been verified live (mirroring how LaunchSpec was
// populated incrementally). It is vacuously green in Phase 0 (no
// ResumeNative row exists yet); that is intended — the pin arms the
// invariant before Phase 3 grounds the first native-resume tool.
func TestNativeResumeGrounded(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Resume.Kind != integration.ResumeNative {
			continue
		}
		if c.Resume.Subcommand == "" {
			t.Errorf("adapter %q: ResumeNative but Subcommand empty", c.Tool)
		}
		if c.Resume.IDMechanism == "" {
			t.Errorf("adapter %q: ResumeNative but IDMechanism empty (name how the session id is passed)", c.Tool)
		}
	}
}

// TestReadersImplemented pins the shipped reader tranches: P1 (claude-code,
// codex) + the P2 tranche (cursor, cline, cline-cli, hermes, opencode).
func TestReadersImplemented(t *testing.T) {
	implemented := map[string]bool{}
	for _, a := range adapterdefaults.Adapters() {
		if _, ok := a.(transcriptReader); ok {
			implemented[a.Name()] = true
		}
	}
	for _, want := range []string{
		"claude-code", "codex", // P1
		"cursor", "cline", "cline-cli", "hermes", "opencode", // P2 tranche 2
	} {
		if !implemented[want] {
			t.Errorf("adapter %q must implement ReadTranscript (shipped tranche)", want)
		}
	}
}

// TestEveryLaunchableToolHasBinarySpec pins the binary-resolution coverage
// invariant: every adapter startable in the dashboard's embedded web
// terminal (Handoff.Launch != nil) MUST carry a grounded BinaryResolveSpec
// with at least one Unix binary name — the `observer <x>` launcher's
// resolution ladder (internal/toolresolve, Phase 2) dispatches on this row,
// so a launchable tool without one would resolve nothing. It mirrors
// TestLaunchableImpliesInjectPrompt: a launch capability without its
// resolution data is an incoherent row.
func TestEveryLaunchableToolHasBinarySpec(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if !c.Handoff.Launchable() {
			continue
		}
		if c.Binary == nil {
			t.Errorf("adapter %q: Launch set but Binary (BinaryResolveSpec) is nil", c.Tool)
			continue
		}
		if len(c.Binary.Names.Unix) == 0 {
			t.Errorf("adapter %q: Binary.Names.Unix is empty (a launchable tool needs at least one Unix binary name)", c.Tool)
		}
	}
}

// TestBinarySpecHonesty pins the honesty rules on every populated Binary
// row: install hints are complete (Argv + Display + Channel all present —
// never a fabricated/half-grounded command), probe dirs are HOME-RELATIVE
// and traversal-safe (non-empty, not absolute, no ".." segment), and every
// declared Windows spelling is non-empty. It walks every non-nil Binary,
// not just launchable rows, so a future non-launch resolution row is held
// to the same bar.
func TestBinarySpecHonesty(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, h := range c.Binary.Installs {
			if len(h.Argv) == 0 {
				t.Errorf("adapter %q: Installs[%d] has empty Argv", c.Tool, i)
			}
			if h.Display == "" {
				t.Errorf("adapter %q: Installs[%d] has empty Display", c.Tool, i)
			}
			if h.Channel == "" {
				t.Errorf("adapter %q: Installs[%d] has empty Channel", c.Tool, i)
			}
		}
		for i, p := range c.Binary.ProbeDirs {
			if p.Rel == "" {
				t.Errorf("adapter %q: ProbeDirs[%d].Rel is empty", c.Tool, i)
			}
			if filepath.IsAbs(p.Rel) {
				t.Errorf("adapter %q: ProbeDirs[%d].Rel %q is absolute (must be HOME-relative)", c.Tool, i, p.Rel)
			}
			if strings.HasPrefix(p.Rel, "/") {
				t.Errorf("adapter %q: ProbeDirs[%d].Rel %q has a leading '/' (must be HOME-relative, not rooted)", c.Tool, i, p.Rel)
			}
			if strings.Contains(p.Rel, "\\") {
				t.Errorf("adapter %q: ProbeDirs[%d].Rel %q contains a backslash — Rel is always '/'-separated, even for a Windows-OS probe dir (2026-09-02 dashboard-install-gap-remediation research §1.3)", c.Tool, i, p.Rel)
			}
			for _, seg := range strings.Split(p.Rel, "/") {
				if seg == ".." {
					t.Errorf("adapter %q: ProbeDirs[%d].Rel %q contains a '..' segment", c.Tool, i, p.Rel)
				}
			}
		}
		for i, w := range c.Binary.Names.Windows {
			if w == "" {
				t.Errorf("adapter %q: Names.Windows[%d] is empty", c.Tool, i)
			}
		}
	}
}

// TestGuidedInstallGapClosed pins the 2026-08-07 fix (parity plan §15.6a):
// muse, prime-agent, and kimi-code each carry at least one grounded
// InstallHint. This is a regression guard specifically for the class of miss
// that produced the gap — a launchable adapter landing with `Binary.Names`
// set but `Installs` left nil "for later" (never caught by
// TestEveryLaunchableToolHasBinarySpec, which only requires the Names) — plus
// a targeted check on prime-agent that its hint is not the fabricated
// `npm install -g prime-agent` command this test would have caught: that
// package was never published to the public npm registry
// (registry.npmjs.org/prime-agent 404s), even though the tool's local
// install is npm-package-SHAPED. See the new-adapter-checklist §3.6 "npm ls
// -g-proves-a-local-shape trap" for the general caution this leaves behind.
func TestGuidedInstallGapClosed(t *testing.T) {
	for _, tool := range []string{"muse", "prime-agent", "kimi-code"} {
		c, ok := integration.For(tool)
		if !ok {
			t.Fatalf("adapter %q has no registry row", tool)
		}
		if c.Binary == nil {
			t.Fatalf("adapter %q: Binary is nil", tool)
		}
		if len(c.Binary.Installs) == 0 {
			t.Errorf("adapter %q: Installs is empty — the guided-install gap has regressed", tool)
		}
	}

	primeAgent, ok := integration.For("prime-agent")
	if !ok {
		t.Fatal("prime-agent has no registry row")
	}
	for i, h := range primeAgent.Binary.Installs {
		if h.Channel == "npm" {
			t.Errorf("prime-agent: Installs[%d] uses Channel %q — prime-agent has never been published to the public npm registry (registry.npmjs.org/prime-agent 404s); the grounded channel is the vendor's install script", i, h.Channel)
		}
	}
}

// authEnvClosureOwnedKeys are the launcher-closure-owned routing/profile env
// keys that AuthEnv must never carry — they are forwarded by the tool-specific
// attach closures (claudeAttachEnv / codexAttachEnv) or the proxy-route seam,
// not the credential-forwarding path. Mixing them into AuthEnv would double-
// forward (and, for the base URL, risk overriding the daemon's route).
var authEnvClosureOwnedKeys = map[string]bool{
	"ANTHROPIC_BASE_URL":   true,
	"CLAUDE_CONFIG_DIR":    true,
	"ANTHROPIC_CONFIG_DIR": true,
	"CODEX_HOME":           true,
}

// TestAuthEnvWellFormed pins the honesty + hygiene rules on every AuthEnv row:
// each entry is a bare env-var NAME (never a value) — non-empty, no `=`, no
// whitespace, not OBSERVER_-prefixed, not one of the launcher-closure-owned
// routing/profile keys — and a row carries no intra-row duplicate. This is the
// guardrail behind the "NAMES only, never values" contract on Capability.AuthEnv.
func TestAuthEnvWellFormed(t *testing.T) {
	for _, c := range integration.Capabilities() {
		seen := map[string]bool{}
		for i, k := range c.AuthEnv {
			switch {
			case k == "":
				t.Errorf("adapter %q: AuthEnv[%d] is empty", c.Tool, i)
			case strings.ContainsAny(k, "="):
				t.Errorf("adapter %q: AuthEnv[%d] = %q contains '=' (a NAME, never a KEY=VALUE)", c.Tool, i, k)
			case strings.ContainsAny(k, " \t\n\r"):
				t.Errorf("adapter %q: AuthEnv[%d] = %q contains whitespace", c.Tool, i, k)
			case strings.HasPrefix(k, "OBSERVER_"):
				t.Errorf("adapter %q: AuthEnv[%d] = %q is OBSERVER_-prefixed (internal, never a credential env)", c.Tool, i, k)
			case authEnvClosureOwnedKeys[k]:
				t.Errorf("adapter %q: AuthEnv[%d] = %q is a launcher-closure-owned routing/profile key (forwarded elsewhere)", c.Tool, i, k)
			}
			if seen[k] {
				t.Errorf("adapter %q: AuthEnv has a duplicate %q", c.Tool, k)
			}
			seen[k] = true
		}
	}
}

// TestAuthEnvImpliesAttachable pins that credential-env is declared ONLY on an
// attachable row: forwarding is a property of the attach socket (the daemon-
// spawned child does not inherit the caller's os.Environ()), so a bare-only tool
// has nothing to forward across and must carry no AuthEnv.
func TestAuthEnvImpliesAttachable(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if len(c.AuthEnv) == 0 {
			continue
		}
		if c.Attach == nil {
			t.Errorf("adapter %q: AuthEnv set (%v) but the row is not attachable (Attach == nil)", c.Tool, c.AuthEnv)
		}
	}
}

// TestCrossOSRouteOnlyForPersistedKinds pins that ProxyRoute.CrossOSBridge
// is set only on the PERSISTED route kinds — RouteEnvSettings (claude-code
// → ~/.claude/settings.json) and RouteConfigFile (codex →
// ~/.codex/config.toml). The `<tool>-windows` virtual target writes the
// route into a foreign Windows home over crossmount; that only makes sense
// for a route backed by a config FILE observer writes, never a launcher
// env var (RouteLauncher) or an operator-pasted instruction (RouteManual).
func TestCrossOSRouteOnlyForPersistedKinds(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Proxy == nil || !c.Proxy.CrossOSBridge {
			continue
		}
		switch c.Proxy.Kind {
		case integration.RouteEnvSettings, integration.RouteConfigFile:
			// persisted config write — cross-OS bridging is coherent.
		default:
			t.Errorf("adapter %q: Proxy.CrossOSBridge set on non-persisted RouteKind %q", c.Tool, c.Proxy.Kind)
		}
	}
}

// registryKeys reads the keys of internal/integration's package-level
// `registry` map straight out of the source. There is no exported accessor
// for them (For/Capabilities both hand back values), and the KEY is what
// every caller looks a tool up by — so a test that only ever sees values
// cannot notice a row filed under the wrong key.
func registryKeys(t *testing.T) []string {
	t.Helper()
	keys, err := conformast.MapKeys(".", "registry")
	if err != nil {
		t.Fatalf("reading the registry map keys: %v", err)
	}
	if len(keys) < 20 {
		t.Fatalf("only %d registry keys extracted — the registry shape probably changed", len(keys))
	}
	return keys
}

// TestRegistryRowToolMatchesItsKey closes the free-ride hole the codex
// review found: TestRegistryCoversEveryRegisteredAdapter only asserts that
// For(name) RESOLVES, so a row filed under "new-tool" but carrying
// Tool: "codex" satisfies it — and then every capability keyed on
// Capability.Tool (proxy route, handoff lane, launcher verb, and this file's
// Vocabulary check) silently reads codex's answers for a different adapter.
//
// The key IS the identity: internal/integration.For, the doctor, the
// dashboard matrix and sessions.tool all address a row by it.
func TestRegistryRowToolMatchesItsKey(t *testing.T) {
	for _, key := range registryKeys(t) {
		c, ok := integration.For(key)
		if !ok {
			t.Errorf("registry key %q does not resolve through For", key)
			continue
		}
		if c.Tool != key {
			t.Errorf("registry row keyed %q carries Tool %q — the row would free-ride on "+
				"%q's capabilities everywhere Capability.Tool is the lookup", key, c.Tool, c.Tool)
		}
	}
}

// toolSpecificTooltaxRows counts the rows internal/tooltax carries for a
// SPECIFIC tool. It deliberately does not use tooltax.For, which folds in
// the tool-less fallback rows that apply to every adapter — those say
// nothing about whether THIS adapter's vocabulary was canonicalized.
func toolSpecificTooltaxRows(tool string) int {
	n := 0
	for _, e := range tooltax.Table() {
		if e.Tool == tool {
			n++
		}
	}
	return n
}

// TestVocabularyDeclaredForEveryAdapter is the WP-T3 taxonomy teeth
// (docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §2 and §6):
// every registry row must DECLARE whether its adapter's native tool names
// live in the canonical taxonomy table, and the declaration is verified
// against the real table — a new adapter that adds a registry row without
// adding its vocabulary to internal/tooltax goes red here.
//
// The honesty rule is enforced in BOTH directions:
//
//   - a zero-value Vocabulary (neither InTaxonomy nor a Note) is undeclared
//     and fails — the same "state your capability" pressure Binary /
//     Handoff / Routability already apply;
//   - InTaxonomy true with no TOOL-SPECIFIC tooltax rows is a fabricated
//     capability (the tool-less fallback rows do not count);
//   - InTaxonomy false REQUIRES a Note, and tooltax must genuinely carry no
//     tool-specific rows for it (the five browser-chat `*-web` adapters,
//     whose capture has no tool-call surface at all).
func TestVocabularyDeclaredForEveryAdapter(t *testing.T) {
	for _, c := range integration.Capabilities() {
		rows := toolSpecificTooltaxRows(c.Tool)
		v := c.Vocabulary
		if !v.Declared() {
			t.Errorf("adapter %q: Vocabulary is undeclared — set InTaxonomy true "+
				"(and add its native tool names to internal/tooltax), or set a Note "+
				"explaining the honest zero (tooltax currently has %d tool-specific rows for it)",
				c.Tool, rows)
			continue
		}
		if v.InTaxonomy && rows == 0 {
			t.Errorf("adapter %q: Vocabulary.InTaxonomy is true but internal/tooltax "+
				"carries no tool-specific rows for it — add the adapter's native tool "+
				"names to tooltax's table, or declare the honest zero with a Note", c.Tool)
		}
		if !v.InTaxonomy {
			if v.Note == "" {
				t.Errorf("adapter %q: Vocabulary.InTaxonomy is false without a Note — "+
					"an honest zero must say WHY the adapter has no native tool names", c.Tool)
			}
			if rows > 0 {
				t.Errorf("adapter %q: Vocabulary declares an honest zero (%q) but "+
					"internal/tooltax carries %d tool-specific rows for it — flip "+
					"InTaxonomy to true", c.Tool, v.Note, rows)
			}
		}
	}
}

// honestZeroPackages maps a registry tool that declares
// Vocabulary{InTaxonomy: false} onto the adapter package that captures it.
// It is the evidence base for TestHonestZeroVocabularyHasNoClassifier: an
// honest zero is a claim about the adapter's CODE ("this capture has no
// native tool names"), so the test checks the code.
//
// All five browser-chat rows share one package — internal/adapter/
// browserchat, where the site is the data discriminator, not a separate
// parser per tool.
var honestZeroPackages = map[string]string{
	"chatgpt-web":    "../adapter/browserchat",
	"claude-web":     "../adapter/browserchat",
	"perplexity-web": "../adapter/browserchat",
	"gemini-web":     "../adapter/browserchat",
	"copilot-web":    "../adapter/browserchat",
	"junie":          "../adapter/junie",
	"grokbot":        "../adapter/grokbot",
}

// TestHonestZeroVocabularyHasNoClassifier gives the honest-zero branch
// teeth. Before this, Vocabulary{Note: "..."} passed on any non-empty
// string, so a NEW adapter shipping a real private action-type map could
// declare "no native vocabulary" and skip the taxonomy entirely — the exact
// bypass the codex review named.
//
// The claim is now checked against the source: the adapter's package must
// contain NO name-based action classifier (no switch whose case bodies
// return models.Action*, no package-level map whose values are
// models.Action*), found by AST walk rather than by being told where to
// look. An honest-zero row whose package is not in honestZeroPackages fails
// with instructions, so the mapping cannot be skipped either.
//
// The detector is deliberately CONSERVATIVE: it reports ANY switch/map that
// turns a string into a models.Action*, not only ones that switch on a tool
// name — AST alone cannot tell a tool-name switch from, say, a
// content-block-type switch. An honest-zero package that grows such a
// switch will trip this, and that is the intended outcome: a human decides
// whether the "no native vocabulary" claim still holds, rather than a
// heuristic deciding it silently.
func TestHonestZeroVocabularyHasNoClassifier(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Vocabulary.InTaxonomy {
			continue
		}
		dir, mapped := honestZeroPackages[c.Tool]
		if !mapped {
			t.Errorf("adapter %q declares an honest-zero Vocabulary but has no entry in "+
				"honestZeroPackages — add one pointing at its adapter package so the "+
				"claim can be checked against the code", c.Tool)
			continue
		}
		domains, err := conformast.ActionClassifierDomain(dir)
		if err != nil {
			t.Errorf("adapter %q: scanning %s for a classifier: %v", c.Tool, dir, err)
			continue
		}
		for site, names := range domains {
			t.Errorf("adapter %q declares an honest-zero Vocabulary (%q) but %s ships a "+
				"name-based action classifier at %s with domain %q — the claim is false; "+
				"add those names to internal/tooltax and set InTaxonomy true",
				c.Tool, c.Vocabulary.Note, dir, site, names)
		}
	}
}

// TestVocabularyRowsResolveToRegisteredActionTypes pins that a declared
// vocabulary is USABLE, not just present: every tool-specific tooltax row
// must carry an action type the canonical registry knows. A typo'd action
// type would otherwise sit in the table forever, silently rendering as a
// gray meta chip (CategoryForActionType falls back to `meta` by design).
//
// tooltax.ActionUnknown is ALLOWED and deliberate: cursor's `await`,
// copilot-cli's `report_intent` and kiro-cli's `introspect` are explicit
// unknown rows — a tool we have seen and consciously chose not to bucket,
// which is different information from "never seen".
func TestVocabularyRowsResolveToRegisteredActionTypes(t *testing.T) {
	registered := map[string]bool{}
	for _, at := range tooltax.ActionTypes() {
		registered[at] = true
	}
	for _, c := range integration.Capabilities() {
		if !c.Vocabulary.InTaxonomy {
			continue
		}
		for _, e := range tooltax.Table() {
			if e.Tool != c.Tool {
				continue
			}
			if !registered[e.ActionType] {
				t.Errorf("adapter %q: tooltax row %q carries unregistered action type %q",
					c.Tool, e.Native, e.ActionType)
			}
			if e.Category != tooltax.CategoryForActionType(e.ActionType) {
				t.Errorf("adapter %q: tooltax row %q has category %q but action type %q "+
					"is category %q", c.Tool, e.Native, e.Category, e.ActionType,
					tooltax.CategoryForActionType(e.ActionType))
			}
		}
	}
}

// TestModelSpecGrounded pins a handful of load-bearing, individually
// grounded ModelSpec shapes (B5 model picker) against regression — the
// specific cases the new-adapter checklist / a future edit is most likely
// to silently break: a delivery-kind flip (arg vs env), a missing Lead on
// a subcommand-gated flag, or an explicit ModelNone getting "helpfully"
// filled in without new grounding.
func TestModelSpecGrounded(t *testing.T) {
	want := map[string]integration.ModelSpec{
		// copilot-cli's launcher OWNS --model and translates it to the
		// COPILOT_MODEL env var for the BYOK provider internally — but from
		// the REGISTRY's delivery-mechanism perspective (what the dashboard
		// hands the launcher's argv) it is still ModelArg.
		"copilot-cli": {Kind: integration.ModelArg, Flag: "--model"},
		// goose's --model flag is reachable only under the headless `goose
		// run` one-shot subcommand; the default interactive lane's only
		// grounded mechanism is the GOOSE_MODEL env var.
		"goose": {Kind: integration.ModelEnv, EnvVar: "GOOSE_MODEL"},
		// kiro-cli's --model flag exists only on the `chat` subcommand.
		"kiro-cli": {Kind: integration.ModelArg, Flag: "--model", Lead: []string{"chat"}},
		// openclaw: no grounded seed-time model mechanism.
		"openclaw": {Kind: integration.ModelNone},
		// droid: --model exists only under the headless `droid exec`
		// subcommand, not the interactive default `droid` launch.
		"droid": {Kind: integration.ModelNone},
		"claude-code": {
			Kind: integration.ModelArg, Flag: "--model",
			Known: []string{"opus", "sonnet", "fable"},
		},
		"codex": {Kind: integration.ModelArg, Flag: "--model", Known: []string{"o3"}},
	}
	for tool, spec := range want {
		c, ok := integration.For(tool)
		if !ok {
			t.Errorf("tool %q has no registry row", tool)
			continue
		}
		got := c.Model
		if got.Kind != spec.Kind {
			t.Errorf("%q: Model.Kind = %q, want %q", tool, got.Kind, spec.Kind)
		}
		if spec.Kind == integration.ModelArg && got.Flag != spec.Flag {
			t.Errorf("%q: Model.Flag = %q, want %q", tool, got.Flag, spec.Flag)
		}
		if spec.Kind == integration.ModelEnv && got.EnvVar != spec.EnvVar {
			t.Errorf("%q: Model.EnvVar = %q, want %q", tool, got.EnvVar, spec.EnvVar)
		}
		if !equalStringSlices(got.Lead, spec.Lead) {
			t.Errorf("%q: Model.Lead = %v, want %v", tool, got.Lead, spec.Lead)
		}
		if len(spec.Known) > 0 && !equalStringSlices(got.Known, spec.Known) {
			t.Errorf("%q: Model.Known = %v, want %v", tool, got.Known, spec.Known)
		}
	}
}

// equalStringSlices treats nil and empty as equal (Lead/Known are commonly
// left as a nil zero value rather than an explicit empty slice).
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestModelSpecStructurallyValid walks every registry row and pins the
// internal consistency of a populated ModelSpec: ModelArg must resolve to a
// usable flag (an explicit Flag, or the "--model" default ModelLaunch
// falls back to when Flag is empty — never both empty AND unusable), and
// ModelEnv must carry a non-empty EnvVar (ModelLaunch has no default to
// fall back to for the env case, unlike Flag). This is the shape-level
// mirror of TestNativeResumeGrounded / TestAttachImpliesLauncher: a
// populated capability whose delivery data is unusable is a bug, not a
// valid honest-zero.
func TestModelSpecStructurallyValid(t *testing.T) {
	for _, c := range integration.Capabilities() {
		switch c.Model.Kind {
		case integration.ModelNone:
			// The honest floor — no further shape to check.
		case integration.ModelArg:
			// Flag empty is fine (ModelLaunch defaults it to "--model");
			// nothing else to require.
		case integration.ModelEnv:
			if c.Model.EnvVar == "" {
				t.Errorf("adapter %q: Model.Kind is ModelEnv but EnvVar is empty", c.Tool)
			}
		default:
			t.Errorf("adapter %q: Model.Kind is an unknown value %q", c.Tool, c.Model.Kind)
		}
		// Every populated Model spec (Kind != ModelNone) must actually
		// build via ModelLaunch with a plausible model value — this is the
		// same seam the dashboard picker calls, so a row that Kind-checks
		// fine but errors out of ModelLaunch would be a silent dead end.
		if c.Model.Kind != integration.ModelNone {
			if _, _, err := integration.ModelLaunch(c.Model, "sonnet"); err != nil {
				t.Errorf("adapter %q: ModelLaunch(Model, %q) unexpectedly errored: %v", c.Tool, "sonnet", err)
			}
		}
	}
}

// TestSandboxDeclaredForEveryLaunchableAdapter pins the B9 honesty rule
// (plan §2): every row whose Handoff.Launchable() is true must declare
// either a non-empty Sandbox.StateRW or a non-empty Sandbox.Note. A
// launchable tool with a zero-value SandboxSpec (both empty) is an
// undeclared row — the same class of gap TestVocabularyDeclaredForEveryAdapter
// catches for the taxonomy vocabulary, applied to sandbox filesystem
// isolation. Non-launchable rows are untouched: a SandboxSpec only makes
// sense for a tool the dashboard can start in-terminal.
func TestSandboxDeclaredForEveryLaunchableAdapter(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if !c.Handoff.Launchable() {
			continue
		}
		if len(c.Sandbox.StateRW) == 0 && c.Sandbox.Note == "" {
			t.Errorf("adapter %q: launchable but Sandbox is the zero value (no StateRW and no Note) — declare a grounded row or an honest Note", c.Tool)
		}
	}
}

// TestSandboxPathsWellFormed pins that every SandboxSpec.StateRW/StateRO
// entry across the whole registry (not just launchable rows) is a clean,
// HOME-RELATIVE subpath: not absolute, no ".." segment, not "." or "",
// no leading "-" (an argv-injection guard mirroring the ModelLaunch/remote-
// URL discipline elsewhere in the registry), and free of NUL/whitespace/
// control bytes. These are the exact strings a later unit (internal/sandbox)
// composes into `--bind-try <HOME>/<path> <same>` bwrap flags, so a
// malformed entry here would be a malformed flag there.
func TestSandboxPathsWellFormed(t *testing.T) {
	check := func(t *testing.T, tool, field string, i int, p string) {
		t.Helper()
		switch {
		case p == "":
			t.Errorf("adapter %q: Sandbox.%s[%d] is empty", tool, field, i)
			return
		case p == ".":
			t.Errorf("adapter %q: Sandbox.%s[%d] is %q", tool, field, i, p)
			return
		case filepath.IsAbs(p):
			t.Errorf("adapter %q: Sandbox.%s[%d] %q is absolute (must be HOME-relative)", tool, field, i, p)
		case strings.HasPrefix(p, "-"):
			t.Errorf("adapter %q: Sandbox.%s[%d] %q starts with '-' (argv-injection risk)", tool, field, i, p)
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				t.Errorf("adapter %q: Sandbox.%s[%d] %q contains a '..' segment", tool, field, i, p)
			}
		}
		for _, r := range p {
			switch {
			case r == 0:
				t.Errorf("adapter %q: Sandbox.%s[%d] %q contains a NUL byte", tool, field, i, p)
			case r < 0x20 || r == 0x7f:
				t.Errorf("adapter %q: Sandbox.%s[%d] %q contains a control byte", tool, field, i, p)
			case r == ' ' || r == '\t' || r == '\n' || r == '\r':
				t.Errorf("adapter %q: Sandbox.%s[%d] %q contains whitespace", tool, field, i, p)
			}
		}
	}
	for _, c := range integration.Capabilities() {
		for i, p := range c.Sandbox.StateRW {
			check(t, c.Tool, "StateRW", i, p)
		}
		for i, p := range c.Sandbox.StateRO {
			check(t, c.Tool, "StateRO", i, p)
		}
	}
}

// TestLifecycleVocabularyClosed pins that every registry row's Lifecycle is
// one of the three closed-vocabulary values (lifecycle.go). A hand-typed
// status ("sunset", "DEAD") would silently read as NOT active on every
// Advertised() call — hiding the row from the picker, the guided install and
// `observer init` — while rendering as itself on the matrix. Catching it here
// makes the typo loud instead of invisible.
func TestLifecycleVocabularyClosed(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if !c.Lifecycle.Valid() {
			t.Errorf("adapter %q: Lifecycle = %q is outside the closed vocabulary "+
				"(active / deprecated / dead)", c.Tool, string(c.Lifecycle))
		}
	}
	for _, p := range integration.ProductLifecycles() {
		if !p.Lifecycle.Valid() {
			t.Errorf("product %q: Lifecycle = %q is outside the closed vocabulary "+
				"(active / deprecated / dead)", p.ID, string(p.Lifecycle))
		}
	}
}

// TestLifecycleNotesGrounded pins the EVIDENCE rule of the harness lifecycle
// policy: a non-active status is a claim about a vendor, and a claim without
// a dated, linked source is exactly the unsourced assertion the registry's
// honesty rule forbids. So every non-active registry row AND every
// productLifecycles entry must carry a Note containing a "20"-prefixed date
// (e.g. "2026-04-21") and an "http" source. Active rows may carry a Note (an
// alias / name-collision caveat) but are not required to — there is no claim
// to ground.
func TestLifecycleNotesGrounded(t *testing.T) {
	grounded := func(t *testing.T, what, note string) {
		t.Helper()
		if strings.TrimSpace(note) == "" {
			t.Errorf("%s: a non-active lifecycle requires a grounded Note (reason + date + URL)", what)
			return
		}
		if !strings.Contains(note, "20") {
			t.Errorf("%s: lifecycle Note carries no 20xx- date: %q", what, note)
		}
		if !strings.Contains(note, "http") {
			t.Errorf("%s: lifecycle Note carries no http source: %q", what, note)
		}
	}
	for _, c := range integration.Capabilities() {
		if c.Lifecycle == integration.LifecycleActive {
			continue
		}
		grounded(t, "adapter "+c.Tool, c.LifecycleNote)
	}
	for _, p := range integration.ProductLifecycles() {
		grounded(t, "product "+p.ID, p.Note)
	}
}

// TestProductLifecyclesReferenceRegistryAdapters pins the rowless-product
// table's four structural rules:
//
//   - Adapter is "" (nothing reads this product's data) or a REAL registry
//     tool — never a name that resolves to nothing, which would tell an
//     operator their data is serviced by a parser that does not exist;
//   - ID is NOT itself a registry tool — a product with a row carries its
//     lifecycle ON the row (LifecycleFor prefers the row, so a colliding
//     entry would be dead data);
//   - Lifecycle is never active — an active product with no row is simply an
//     unknown product, not a lifecycle fact worth shipping;
//   - every id in registryRowlessTaxonomyTools (the FROZEN set of tools
//     tooltax knows and the registry deliberately does not) has an entry
//     here, so a retag identity can never be lifecycle-invisible.
func TestProductLifecyclesReferenceRegistryAdapters(t *testing.T) {
	tools := map[string]bool{}
	for _, tool := range integration.Tools() {
		tools[tool] = true
	}
	covered := map[string]bool{}
	for _, p := range integration.ProductLifecycles() {
		covered[p.ID] = true
		if p.ID == "" {
			t.Error("product lifecycle entry with an empty ID")
		}
		if p.Adapter != "" && !tools[p.Adapter] {
			t.Errorf("product %q: Adapter %q is not a registry tool", p.ID, p.Adapter)
		}
		if tools[p.ID] {
			t.Errorf("product %q also has a registry row — carry Lifecycle/LifecycleNote on the row instead "+
				"(LifecycleFor prefers the row, so this entry is unreachable)", p.ID)
		}
		if p.Lifecycle == integration.LifecycleActive {
			// An ACTIVE product with no registry row is normally just an
			// unknown product. The one sanctioned exception is an
			// acknowledged RETAG identity (registryRowlessTaxonomyTools):
			// a live product whose data an existing adapter parses under
			// a different sessions.tool value — it has no adapter identity
			// to carry a row, but Observer must still be able to say the
			// vendor ships it (zoo-code is the first; roo-code was the
			// same shape while alive).
			if _, retag := registryRowlessTaxonomyTools[p.ID]; !retag || p.Adapter == "" {
				t.Errorf("product %q: Lifecycle is active — an active product with no registry row is just an "+
					"unknown product unless it is an acknowledged retag (registryRowlessTaxonomyTools) naming "+
					"its servicing Adapter; drop the entry or give it a row", p.ID)
			}
		}
	}
	for id := range registryRowlessTaxonomyTools {
		if !covered[id] {
			t.Errorf("rowless taxonomy tool %q has no product lifecycle entry — Observer parses its data but "+
				"cannot say whether the vendor still ships it", id)
		}
	}
}

// TestUnadvertisedRowsAreNeverDispatched is the policy's teeth: a row the
// vendor deprecated or killed must be invisible to every ADVERTISING surface
// no matter how complete its capability shape is.
//
// Half one is synthetic: a Capability carrying a full Launch/Attach/Binary/
// Hook/MCP/Proxy shape, flipped through each non-active lifecycle, must read
// as neither TerminalLaunchable nor Advertised. Shape can never outvote
// lifecycle.
//
// Half two sweeps the REAL registry: every non-active row must be absent from
// the launch / install / init dispatch predicates. Today no shipped row is
// non-active, so the loop body does not execute — that is intentional. It is
// the tripwire that fires the moment the first row is flipped, rather than a
// test written after the fact.
func TestUnadvertisedRowsAreNeverDispatched(t *testing.T) {
	full := func(l integration.Lifecycle) integration.Capability {
		return integration.Capability{
			Tool:        "synthetic-tool",
			Lifecycle:   l,
			Proxy:       &integration.ProxyRoute{Kind: integration.RouteEnvSettings, EnvVar: "SYNTHETIC_BASE_URL", Launcher: "observer synthetic"},
			Routability: integration.RouteStatusRoutableNow,
			Hook:        integration.HookSpec{Mechanism: integration.HookClaudeSettings, AutoWired: true, CrossOSBridge: true},
			MCP:         &integration.MCPTarget{Format: integration.MCPServersJSON, Implemented: true},
			TokenTier:   integration.TokenTier{Best: "proxy"},
			Handoff: integration.HandoffCapability{
				Transcript: integration.TranscriptFull,
				Launch:     &integration.LaunchSpec{Subcommand: "synthetic", Mode: integration.LaunchSeeded},
			},
			Attach: &integration.AttachSpec{Subcommand: "synthetic"},
			Binary: &integration.BinaryResolveSpec{
				Names:    integration.BinaryNames{Unix: []string{"synthetic"}, Windows: []string{"synthetic.exe"}},
				Installs: []integration.InstallHint{{OS: "linux", Channel: "npm", Argv: []string{"npm", "i", "-g", "synthetic"}, Display: "npm i -g synthetic"}},
			},
		}
	}
	for _, l := range []integration.Lifecycle{integration.LifecycleDeprecated, integration.LifecycleDead} {
		t.Run("synthetic "+l.String(), func(t *testing.T) {
			c := full(l)
			// The shape itself is complete — if this stops holding, the test
			// is no longer proving that lifecycle is what vetoed it.
			if !c.Handoff.Launchable() {
				t.Fatal("synthetic row is not shape-launchable — the fixture no longer isolates lifecycle")
			}
			if integration.TerminalLaunchable(c) {
				t.Error("TerminalLaunchable = true for a fully-shaped row on an unadvertised lifecycle")
			}
			if c.Advertised() {
				t.Error("Advertised = true on an unadvertised lifecycle")
			}
		})
	}

	// Real rows: launchable-set membership, guided-install eligibility and
	// init-target eligibility are all downstream of these two predicates, so
	// asserting them here covers every dispatch site without importing cmd.
	for _, c := range integration.Capabilities() {
		if c.Lifecycle.Advertised() {
			continue
		}
		if integration.TerminalLaunchable(c) {
			t.Errorf("adapter %q: lifecycle %q but TerminalLaunchable = true — it would still be offered "+
				"in the New Terminal picker", c.Tool, string(c.Lifecycle))
		}
		if c.Advertised() {
			t.Errorf("adapter %q: lifecycle %q but Advertised = true — it would still be offered for "+
				"guided install and as an `observer init` target", c.Tool, string(c.Lifecycle))
		}
	}

	// Same sweep over the GUI launch table, which composes the row lifecycle
	// into GUILaunchable.Advertised (plan §2.1) — one policy, two surfaces.
	for _, g := range integration.GUILaunchables() {
		if g.Lifecycle.Advertised() {
			continue
		}
		if g.Advertised() {
			t.Errorf("GUI row %q (adapter %q): lifecycle %q but Advertised = true",
				g.Spec.ID, g.Adapter, string(g.Lifecycle))
		}
	}
}
