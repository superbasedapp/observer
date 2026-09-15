package integration

import "sort"

// This file is the HARNESS LIFECYCLE POLICY's data vocabulary
// (docs/harness-lifecycle-policy.md). It answers one question per product
// Observer knows about: does the vendor still ship and support it? The
// answer is a CLOSED, three-value vocabulary carried on every registry row
// (Capability.Lifecycle) and — for products that have no registry row of
// their own (a retag identity, a renamed alias, a dead sibling product
// line) — in the productLifecycles table below.
//
// Every consumer that ADVERTISES a product (the New Terminal picker, the
// guided-install endpoint, `observer init`'s target lists, the launch
// dispatch, the adapters matrix, the doctor) dispatches on this shape via
// Lifecycle.Advertised() / Capability.Advertised() / TerminalLaunchable —
// never on a tool name (CLAUDE.md #3). Capture is NEVER gated on it:
// Observer keeps parsing existing local data for a deprecated or dead
// product and never deletes its rows; only the advertising stops.

// Lifecycle is the vendor-support status of a product. The zero value is
// active so every existing row is active by construction (CLAUDE.md #6 —
// additive, not invasive).
type Lifecycle string

const (
	// LifecycleActive (zero value): the vendor ships and supports the
	// product. Observer advertises install / launch / init for it.
	LifecycleActive Lifecycle = ""
	// LifecycleDeprecated: the vendor announced a sunset, superseded the
	// product, or moved its store — but the product may still run and its
	// local data may still exist. Observer keeps capturing, marks the row
	// DEPRECATED on every surface, and stops advertising install / launch /
	// init (a sunset product is not something to push a new user into).
	LifecycleDeprecated Lifecycle = "deprecated"
	// LifecycleDead: the vendor shut the product down or archived it.
	// Observer keeps parsing existing local data (never deletes rows) but
	// stops advertising install / launch / init, hides the row from the New
	// Terminal picker, marks it DEAD on the adapters matrix / doctor /
	// dashboard, and retires its docs to a "retired" section. Removal of
	// the adapter itself is a SEPARATE, later step (docs/new-adapter-
	// checklist.md "Removing an adapter").
	LifecycleDead Lifecycle = "dead"
)

// Valid reports whether l is one of the closed vocabulary values.
func (l Lifecycle) Valid() bool {
	return l == LifecycleActive || l == LifecycleDeprecated || l == LifecycleDead
}

// String renders the lifecycle for humans; the zero value reads "active".
func (l Lifecycle) String() string {
	if l == LifecycleActive {
		return "active"
	}
	return string(l)
}

// Advertised is THE ONE predicate every advertising surface consults: only
// an active product is offered for install, launch, or as an `observer
// init` target. Deprecated and dead products are both excluded — the two
// differ in wording and in what happens to their docs, not in dispatch
// (docs/harness-lifecycle-policy.md §2). Capture is never gated on it.
func (l Lifecycle) Advertised() bool { return l == LifecycleActive }

// Advertised reports whether this registry row's product is still
// advertised (Lifecycle.Advertised on the row). Consumers that walk the
// registry use this rather than reading Lifecycle directly so the policy
// has exactly one definition.
func (c Capability) Advertised() bool { return c.Lifecycle.Advertised() }

// TerminalLaunchable is the single predicate the embedded-terminal launch
// surfaces (the New Terminal picker, /api/terminal/launch, the preflight
// and guided-install seams, the sandbox tool table) dispatch on: a grounded
// LaunchSpec AND an advertised lifecycle. It replaces bare
// `c.Handoff.Launchable()` checks on those surfaces so a deprecated or
// dead row can never be offered for launch, pinned by
// TestUnadvertisedRowsAreNeverDispatched.
func TerminalLaunchable(c Capability) bool {
	return c.Handoff.Launchable() && c.Advertised()
}

// ProductLifecycle is the lifecycle row for a product that has NO registry
// row of its own but that Observer still has to categorise honestly: a
// retag identity that lands under another adapter's parser (roo-code under
// cline), a renamed alias (windsurf → Devin Desktop), or a dead sibling
// product line that shares a command name with a live one (the legacy
// Python open-interpreter). The registry's honesty rule forbids inventing a
// Capability row for these (every cell would be zero or copied), so their
// lifecycle lives here instead, keyed by the product id the docs and the
// `sessions.tool` column use.
type ProductLifecycle struct {
	// ID is the product id ("roo-code", "windsurf", "open-interpreter-python").
	ID string
	// Adapter is the registry row that services this product's local data
	// ("" when no adapter reads it at all).
	Adapter string
	// Lifecycle is the product's status; never LifecycleActive here (an
	// active product with no row is simply an unknown product).
	Lifecycle Lifecycle
	// Note is the vendor-grounded reason + date + URL (required, pinned by
	// TestLifecycleNotesGrounded).
	Note string
}

// productLifecycles is the rowless-product lifecycle table (CLAUDE.md #5 —
// a data table, one test case per row). A new dead/deprecated product that
// has no adapter row is one entry here; a product that HAS a row carries
// Lifecycle + LifecycleNote on the row instead, never both.
var productLifecycles = map[string]ProductLifecycle{
	"roo-code": {
		ID:        "roo-code",
		Adapter:   "cline",
		Lifecycle: LifecycleDead,
		Note: "Roo Code (RooVeterinaryInc.roo-cline) shut down 2026-04-21; the GitHub repo " +
			"and the VS Code extension were archived read-only 2026-05-15 at v3.54.0 and the " +
			"vendor pivoted to the Slack-only cloud product Roomote (community continuation: " +
			"ZooCode). Observer keeps parsing the existing rooveterinaryinc.roo-cline/tasks " +
			"globalStorage through internal/adapter/cline (a per-file retag, no roo-code " +
			"registry row by design — IDE-20) and never deletes its rows; nothing is " +
			"advertised for it. Sources: https://github.com/RooCodeInc/Roo-Code (archived), " +
			"docs/audits/vendor-surface-inventory-2026-09-03.md §3.3 (MEDIUM confidence — " +
			"third-party corroboration, Roo's own pages are archived).",
	},
	"open-interpreter-python": {
		ID:        "open-interpreter-python",
		Adapter:   "",
		Lifecycle: LifecycleDead,
		Note: "The legacy Python open-interpreter line (pip `open-interpreter`) is no longer " +
			"vendor-maintained as of 2026 and lives on only as the community fork " +
			"endolith/open-interpreter; the vendor's current product is the Rust rewrite " +
			"based on Codex that the `open-interpreter` registry row targets. COMMAND-NAME " +
			"COLLISION: both answer to `interpreter`. Observer's adapter is path-keyed " +
			"(~/.openinterpreter/sessions via INTERPRETER_HOME, a codex retag) and never " +
			"reads the Python line's data; any launcher or detector keyed on the command " +
			"name must disambiguate by binary path / version string. Sources: " +
			"https://pypi.org/project/open-interpreter, https://github.com/endolith/open-interpreter, " +
			"docs/audits/vendor-surface-inventory-2026-09-03.md §3.3.",
	},
	"windsurf": {
		ID:        "windsurf",
		Adapter:   "devin",
		Lifecycle: LifecycleDeprecated,
		Note: "Windsurf was renamed Devin Desktop on 2026-06-02 (Cognition folded the Windsurf " +
			"IDE and the Devin agent into one install). The name survives as an ALIAS only: the " +
			"IDE still installs under %LOCALAPPDATA%\\Programs\\Windsurf with a `windsurf` shim, " +
			"and its bundled devin.exe lane is expected to write ~/.devin (captured by the devin " +
			"row, UNVERIFIED until a logged-in run). The separate Cascade / \"Devin Local\" agent " +
			"store is NOT covered (would be a new tool id — inventory §3.1 #2). Source: " +
			"https://docs.devin.ai/desktop, docs/audits/vendor-surface-inventory-2026-09-03.md §1.5.",
	},
	"gemini-code-assist-individuals": {
		ID:        "gemini-code-assist-individuals",
		Adapter:   "gemini-cli",
		Lifecycle: LifecycleDeprecated,
		Note: "On 2026-06-18 Google stopped serving Gemini CLI and the Gemini Code Assist IDE " +
			"extensions for the free 'for individuals' tier and for Google AI Pro / Ultra " +
			"accounts; those users are directed to the Antigravity family (Antigravity CLI " +
			"`agy` and the Antigravity IDE — Observer rows antigravity-cli / antigravity). " +
			"Gemini Code Assist STANDARD and ENTERPRISE subscriptions are unchanged, so the " +
			"gemini-cli registry row stays ACTIVE (capture, install and launch still valid " +
			"for those tiers); the operator's live attempt 2026-09-03 returned \"This client " +
			"is no longer supported for Gemini Code Assist for individuals\". Sources: " +
			"https://developers.google.com/gemini-code-assist/docs/deprecations/code-assist-individuals, " +
			"https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/.",
	},
	"zoo-code": {
		ID:        "zoo-code",
		Adapter:   "cline",
		Lifecycle: LifecycleActive,
		Note: "ZooCode (ZooCodeOrganization.zoo-code) is the community continuation of Roo Code " +
			"after its 2026-04-21 shutdown, shipped 2026 as a separate VS Code listing; parsed " +
			"by internal/adapter/cline as a per-file retag (no registry row by design, like " +
			"roo-code). Vendor status: active community project — on-disk extension-dir " +
			"spelling still UNCONFIRMED (inventory rates the ext id LOW; the Marketplace id " +
			"ZooCodeOrganization.zoo-code itself is vendor-confirmed). Sources: " +
			"https://www.zoocode.dev/, https://github.com/Zoo-Code-Org/Zoo-Code, " +
			"docs/audits/vendor-surface-inventory-2026-09-03.md §2.6 / §3.3.",
	},
}

// ProductLifecycles returns the rowless-product lifecycle table, sorted by
// ID. The adapters matrix and the doctor render these alongside the
// registry rows so a dead retag identity is visible, not silently absent.
func ProductLifecycles() []ProductLifecycle {
	out := make([]ProductLifecycle, 0, len(productLifecycles))
	for _, p := range productLifecycles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LifecycleFor resolves a product id — a registry tool OR a rowless product
// id — to its lifecycle and grounded note. ok is false for an id Observer
// knows nothing about (the caller decides; the honest floor is "unknown",
// never "active"). A registry row wins over the product table, so the two
// key spaces can never disagree about one id.
func LifecycleFor(id string) (lifecycle Lifecycle, note string, ok bool) {
	if c, found := registry[id]; found {
		return c.Lifecycle, c.LifecycleNote, true
	}
	if p, found := productLifecycles[id]; found {
		return p.Lifecycle, p.Note, true
	}
	return LifecycleActive, "", false
}
