package codex

import (
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// This file resolves the codex rollout's OWNING session_meta
// `originator` / `source` fields into the normalized
// models.Surface* capture-surface vocabulary (Part E of
// docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md,
// IDE-15 provenance half). CLAUDE.md #5 (table-driven, not a growing
// if/else ladder): the resolver below is two lookup tables, never a
// switch on tool identity.
//
// Ground truth (§0 of the plan, 80 live rollouts sampled 2026-09-02;
// REVISED by the 2026-09-06 controlled A/B, plan §13.1): `source ∈
// {exec, vscode, cli}` is the RELIABLE discriminator for `exec`/`cli`
// — `codex_exec|exec` (67/80), `*|cli`. `vscode` covers BOTH the
// standalone desktop app and the VS Code extension, and for years the
// only lever thought to separate them — `originator` — looked
// worthless: every sampled session_meta carrying "Codex Desktop" also
// carried `source:"vscode"`, and the 80-rollout sample never caught a
// session distinguishably from the extension.
//
// The 2026-09-06 A/B settled it: one prompt in the standalone
// Codex/ChatGPT desktop app produced `originator:"Codex Desktop"`,
// `source:"vscode"` (cli_version 0.153.1); one prompt in the
// `openai.chatgpt` VS Code extension produced
// `originator:"codex_vscode"`, `source:"vscode"` (cli_version
// 0.151.0-alpha.7.2). They are CLEANLY DISTINCT — "Codex Desktop" IS
// the standalone desktop app, not a VS Code extension alias, and
// `codex_vscode` IS the extension. Both inherit `source:"vscode"`
// because `source` is a KIND discriminator (this codex binary is
// embedded in *some* editor-adjacent host), not a HOST discriminator
// — see the JetBrains counter-example below for the same shape. So
// "Codex Desktop" is now an AUTHORITATIVE originator row resolving to
// `desktop`/`codex-desktop`, overriding the inherited `source:"vscode"`
// pre-fill exactly the way the JetBrains rows already did;
// `codex_vscode` is unchanged (`ide`/`vscode`). `originator` still
// refines the HOST token where `source` alone is ambiguous (the CLI
// binary's originator has been observed as both "codex_cli" and, in
// this repo's own testdata fixtures, "codex_cli_rs").
//
// `source` is reliable for the KIND but NOT always for the HOST. The
// counter-example (grounded 2026-09-03, a live rollout driven from
// IntelliJ IDEA 2026.2's AI Assistant) is
// `{"originator":"JetBrains.IntelliJ IDEA","source":"vscode"}`: the
// JetBrains plugin drives the same codex binary, which stamps the
// inherited `source:"vscode"` regardless of who embedded it. Resolving
// from `source` alone stamped that session `ide`/`vscode` — the right
// KIND with the WRONG HOST. So an originator row that names its host
// AUTHORITATIVELY (surfaceRow.authoritative) is consulted first and
// overrides the source pre-fill; every other originator keeps the
// pre-existing source-first precedence.

// surfaceRow is one resolved (kind, host) pair.
type surfaceRow struct {
	kind string
	host string
	// authoritative marks an originator row whose HOST is more
	// specific than anything `source` can express, so it wins over a
	// source pre-fill instead of only refining an ambiguous one. Only
	// meaningful on originator rows; ignored on codexSourceSurface.
	//
	// Deliberately NOT set on the codex_* rows: for those, `source`
	// remains the grounded discriminator (an `exec` run and a `cli`
	// run of the same binary differ by source, not by originator), so
	// flagging them would invert a precedence the 80-rollout sample
	// supports.
	authoritative bool
}

// codexSourceSurface maps the reliable `source` field to a fixed
// Surface KIND. host is pre-filled where every observed originator
// under that source resolves to the same host token (exec, vscode);
// left "" for cli, where resolveCodexSurface refines the host from
// codexOriginatorHost instead.
var codexSourceSurface = map[string]surfaceRow{
	"cli":  {kind: models.SurfaceCLI, host: ""},
	"exec": {kind: models.SurfaceCLI, host: "codex-exec"},
	// "vscode" is the pre-fill for the VS Code extension
	// (originator "codex_vscode"). "Codex Desktop" also inherits
	// `source:"vscode"` (source is a KIND discriminator, not a HOST
	// one — see the file doc comment above), but its
	// codexOriginatorHost row is authoritative and overrides this
	// pre-fill before it is ever consulted.
	"vscode": {kind: models.SurfaceIDE, host: "vscode"},
}

// codexOriginatorHost is the originator-keyed table. It serves two
// roles: (1) refines the host when source=="cli" above, and (2) is
// the sole resolver when `source` is empty or not one of the three
// known values (an older codex build, or a future value this table
// hasn't seen yet).
//
// Note on the Open Interpreter rebadge (codex.NewOpenInterpreter):
// this table is codex PROPER's vocabulary. SessionSurface carries no
// Tool field (unlike ToolEvent/TokenEvent, it is never retagged by
// ParseSessionFile's variant pass), so a variant that owns its own
// originator token declares it as a surfaceVocabulary overlay
// (openinterpreter.go) consulted BEFORE these tables — that is how
// the Interpreter desktop app's "codex_ui" resolves to
// desktop/"open-interpreter" on the variant while staying UNMAPPED
// here: it is not known whether some OpenAI surface also writes it,
// and codex proper emits no stamp for a token it cannot attribute.
// A variant with no overlay row still lands on these codex-* tokens,
// which is the honest answer for a shared-lineage rebadge with no
// grounded discriminator of its own.
var codexOriginatorHost = map[string]surfaceRow{
	"codex_cli":    {kind: models.SurfaceCLI, host: "codex-cli"},
	"codex_cli_rs": {kind: models.SurfaceCLI, host: "codex-cli"},
	"codex_exec":   {kind: models.SurfaceCLI, host: "codex-exec"},
	"codex_vscode": {kind: models.SurfaceIDE, host: "vscode"},
	// "Codex Desktop" is the standalone Codex/ChatGPT desktop app
	// (2026-09-06 A/B, plan §13.1) — cleanly distinct from the VS
	// Code extension's "codex_vscode" originator even though both
	// inherit `source:"vscode"`. Authoritative so it overrides the
	// inherited source pre-fill (see codexSourceSurface["vscode"]).
	"Codex Desktop": {kind: models.SurfaceDesktop, host: "codex-desktop", authoritative: true},
}

// lookupCodexOriginator resolves one `originator` token, in two
// table-driven steps: the literal codexOriginatorHost rows above,
// then the JetBrains client-name rule.
//
// The JetBrains rule is not a hard-coded product list here — it
// delegates to internal/platform/jetbrainshost, the ONE owner of
// JetBrains host vocabulary, so `JetBrains.IntelliJ IDEA` →
// "jetbrains-idea", `JetBrains.GoLand` → "jetbrains-goland", and any
// `JetBrains.<unknown product>` → the generic "jetbrains", all
// resolved from that package's own product table. Rows minted this
// way are authoritative: the IDE that embedded the binary is a
// stronger statement about the host than the inherited `source`.
func lookupCodexOriginator(originator string) (surfaceRow, bool) {
	if row, hit := codexOriginatorHost[originator]; hit {
		return row, true
	}
	if host, hit := jetbrainshost.HostForClientName(originator); hit {
		return surfaceRow{kind: models.SurfaceIDE, host: host, authoritative: true}, true
	}
	return surfaceRow{}, false
}

// resolveCodexSurface resolves the owning session_meta's `source` +
// `originator` fields into (kind, host).
//
// Precedence: an AUTHORITATIVE originator row wins outright (see the
// surfaceRow.authoritative doc and the JetBrains counter-example in
// the file header). Otherwise source is tried first; when it's known
// but its host is ambiguous (cli), originator refines the host. When
// source is empty/unrecognized, originator alone resolves both kind
// and host. Neither known → ok=false: the caller must emit no
// SessionSurface row rather than guess (the SessionSurface contract's
// honesty rule).
func resolveCodexSurface(source, originator string) (kind, host string, ok bool) {
	oRow, oHit := lookupCodexOriginator(originator)
	if oHit && oRow.authoritative {
		return oRow.kind, oRow.host, true
	}
	if row, hit := codexSourceSurface[source]; hit {
		if row.host != "" {
			return row.kind, row.host, true
		}
		if oHit {
			return row.kind, oRow.host, true
		}
		// source resolved a kind but originator is unseen — still
		// trust the source-derived kind rather than dropping the row
		// over a host-only gap; fall back to a source-derived host
		// token.
		return row.kind, "codex-" + source, true
	}
	if oHit {
		return oRow.kind, oRow.host, true
	}
	return "", "", false
}
