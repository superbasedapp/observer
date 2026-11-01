package proxyroute

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// ProviderName is the custom codex model_provider key our routing
// config registers. Codex 0.128.0+ rejects overriding the reserved
// built-in `openai` provider (config-load fails with
// "model_providers contains reserved built-in provider IDs"), so we
// register a sibling provider and switch model_provider to it.
const ProviderName = "openai-observer"

// providerDisplayName is what shows up in codex's TUI provider picker.
const providerDisplayName = "OpenAI (via Observer)"

// RegisterOptions parameterizes Registrar.
type RegisterOptions struct {
	// ProxyPort is the port the observer proxy listens on (e.g. 8820).
	// Required when codex registration is invoked.
	ProxyPort int
	// HomeDir overrides $HOME (used by tests).
	HomeDir string
	// DryRun computes the result without writing.
	DryRun bool
	// Force overwrites an existing model_providers.<ProviderName>.base_url
	// that points at a different host, deletes a reserved [model_providers.openai]
	// block (which codex 0.128.0+ rejects), and replaces a top-level
	// model_provider that points at a different provider.
	Force bool
	// WindowsClaudeHome / WindowsCodexHome override the auto-detected
	// Windows-side home used by the cross-OS route writers
	// (RegisterClaudeCodeWindows / RegisterCodexWindows in windows.go).
	// Empty = walk crossmount.AllHomes() for the first OS==windows home
	// carrying the tool's config dir (the production path). Set by tests
	// to point at a temp dir; mirrors hook.Options.WindowsClaudeHome /
	// WindowsCursorHome.
	WindowsClaudeHome string
	WindowsCodexHome  string
	// WSLUserHome overrides the auto-detected WSL Linux home the Windows to
	// WSL route twins (RegisterClaudeCodeWSL / RegisterCodexWSL in
	// windows.go) write under, as this Windows host reaches it
	// (\\wsl.localhost\<distro>\home\<user>); the writer appends .claude or
	// .codex. Mirrors hook.Options.WSLUserHome.
	WSLUserHome string
	// Writer says who is writing routes through this registrar (enrolment,
	// `observer init`, Settings > Setup, a launcher). Every write or
	// confirmation is recorded with it in the route-provenance file
	// (provenance.go), which is how leaving an organization removes only the
	// routes enrolment wrote. The zero value is "unknown", never enrolment.
	Writer routeprov.Writer
	// Lock takes the cross-process settings-file lock Observer's own hook
	// and MCP writers take on the same files (internal/hook.LockSettingsFile,
	// injected by the caller). nil locks nothing. Used by RegisterCodex and
	// UnregisterCodex.
	Lock func(path string) (func(), error)
	// Getenv reads the environment variables that relocate a route file
	// (today Cline's CLINE_DATA_DIR / CLINE_DIR for globalState.json). Nil
	// is the one pinned-home rule (crossmount.HomeEnv, R-188 F1): os.Getenv
	// only when the caller did not pin HomeDir and the process home is not
	// isolated from the account's real home (crossmount.IsolationReason,
	// the LEFT2 rule), and NO variables otherwise, so a pinned or isolated
	// home resolves every file under itself (surface-gap Waves 1-3 audit
	// finding 2).
	Getenv func(string) string
	// ClientToken is the proxy client token (OSH-R-009,
	// docs/plans/proxy-client-auth-2026-10-30.md). When set, the writers
	// whose inspection row declares clientAuth (claude-code, codex) write
	// the token form http://127.0.0.1:<port>/t/<token>..., and rewrite a
	// route of theirs that differs from it only in the token prefix. ""
	// writes the plain form, and rewrites a token form back to it.
	ClientToken string
}

// RegistrationResult summarizes one routing registration.
type RegistrationResult struct {
	Tool       string // "codex"
	ConfigPath string // ~/.codex/config.toml
	BaseURL    string // value written or already set; a client token in it is redacted
	Added      bool
	// ClientAuth reports that the route written or found carries the proxy
	// client token (BaseURL shows it redacted).
	ClientAuth bool
	AlreadySet bool
	DryRun     bool
	Error      error
	// ConfigMissing is set by the probe-route writers (kimi-code / crush /
	// qwen-code) when the tool's config file is absent — the tool isn't
	// installed/configured, so there is nothing to route. It is a benign
	// skip signal (Error stays nil), letting `observer init` iterate every
	// registry probe-route candidate and silently pass over the ones the
	// operator doesn't have. The verified writers (codex/claude/hermes)
	// never set it (they error on a missing config instead).
	ConfigMissing bool
	// SkipReason, when non-empty, explains a deliberate no-write that is
	// NOT "the tool isn't installed": today only the cross-OS sandbox gate
	// (a caller pinned HomeDir but named no Windows-side home — see
	// crossmount.AutoDetectSuppressed, incident 2026-07-31). Set alongside
	// ConfigMissing so existing callers keep treating it as a benign skip;
	// Error stays nil.
	SkipReason string
	// PriorBaseURL / UpstreamID / UpstreamRoot are populated by writers that
	// route through a /up/<id> prefix (hermes): the upstream the operator must
	// add to [proxy.upstreams]. Zero for the fixed-upstream writers (codex).
	PriorBaseURL string
	UpstreamID   string
	UpstreamRoot string
	// GatewayHintsAdded is set by the Claude Code writers when they add
	// env.CLAUDE_CODE_GATEWAY_HINT_HEADERS=1 beside the route (claude.go).
	// It can be true alongside AlreadySet: an existing route is topped up
	// with the hint switch without the route itself changing. On an
	// unregister it means the switch was (or would be) removed.
	GatewayHintsAdded bool
	// PriorProvider is Codex's top-level model_provider before this write
	// switched it to Observer's provider ("" when it was unset), recorded so
	// leaving an organization can put it back.
	PriorProvider string
	// ProvenanceError is set when the route was written but recording who
	// wrote it failed. The route stands; Leave then treats it as not written
	// by enrolment and keeps it.
	ProvenanceError error
	// RouteKey / LaneID / LaneRoot are set by the third-party-provider lane
	// writers (lane.go): the config path the route was written at (when it
	// is not the tool's fixed key), the proxy lane it addresses and the
	// upstream host root that lane forwards to. Recorded in provenance so the
	// lane is re-installed at start and the original host restored on
	// removal.
	RouteKey []string
	LaneID   string
	LaneRoot string
}

// Registrar dispatches proxy-routing config writes per tool.
type Registrar struct {
	opts RegisterOptions
	// homeOverride is the caller-supplied RegisterOptions.HomeDir VERBATIM,
	// kept before NewRegistrar defaults it to the real $HOME. Non-empty
	// means "the caller pinned this registrar's home", which switches OFF
	// crossmount auto-detection for the cross-OS "-windows" route writers —
	// see crossmount.AutoDetectSuppressed (incident 2026-07-31).
	homeOverride string
}

// NewRegistrar validates opts and returns a Registrar.
func NewRegistrar(opts RegisterOptions) (*Registrar, error) {
	if opts.ProxyPort <= 0 || opts.ProxyPort > 65535 {
		return nil, fmt.Errorf("proxyroute.NewRegistrar: ProxyPort %d out of range", opts.ProxyPort)
	}
	homeOverride := opts.HomeDir
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("proxyroute.NewRegistrar: UserHomeDir: %w", err)
		}
		opts.HomeDir = home
	}
	opts.Getenv = crossmount.HomeEnv(homeOverride, opts.Getenv)
	return &Registrar{opts: opts, homeOverride: homeOverride}, nil
}

// codexBaseURL is the value we write into the custom provider's base_url.
// Localhost-only because the proxy never accepts non-loopback connections
// (see internal/proxy/proxy.go).
func codexBaseURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/v1", port)
}

// IsObserverBaseURL reports whether url is a 127.0.0.1 base_url that this
// registrar would treat as already-routing-through-observer regardless of
// port. Used to distinguish "user already pointed codex at observer (maybe
// a different port)" from "user pointed codex at a third-party proxy."
func IsObserverBaseURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// RegisterCodex writes a custom [model_providers.openai-observer] block
// into ~/.codex/config.toml and sets top-level model_provider to point
// at it. Idempotent — re-running with the same port returns AlreadySet.
//
// Refuses without Force when:
//   - a [model_providers.openai] block exists (codex 0.128.0+ fails to
//     load that — our write would land in a config codex won't read),
//   - the openai-observer provider points at a non-loopback host, or
//   - the top-level model_provider is set to a third provider.
//
// Other 127.0.0.1 URLs (e.g. user's own observer on a different port)
// are treated as AlreadySet — we don't clobber another local observer
// install by default.
func (r *Registrar) RegisterCodex() RegistrationResult {
	path, err := r.codexConfigPath()
	if err != nil {
		return RegistrationResult{Tool: "codex", BaseURL: codexBaseURL(r.opts.ProxyPort), DryRun: r.opts.DryRun, Error: err}
	}
	return redactResult(r.registerCodexAt(filepath.Dir(path), r.clientAuthURL(codexBaseURL(r.opts.ProxyPort)), "codex"))
}

// registerCodexAt is the parameterized core of RegisterCodex: it writes
// the custom [model_providers.openai-observer] block + top-level
// model_provider into <dir>/config.toml with base_url=<want>, tagging
// the result with toolLabel. The native RegisterCodex passes ~/.codex +
// the loopback /v1 URL + "codex"; the cross-OS RegisterCodexWindows
// (windows.go) passes a Windows-side .codex + the localhost /v1 URL +
// "codex-windows". Behaviour for the native call is byte-identical to
// the pre-refactor method.
func (r *Registrar) registerCodexAt(dir, want, toolLabel string) RegistrationResult {
	return r.note(r.writeCodexAt(dir, want, toolLabel), want)
}

// writeCodexAt is registerCodexAt without the provenance record.
//
// The edit is surgical (T-394, the M3-16 undo's twin): cfgfmt changes only
// the keys this writer owns ([model_providers.openai-observer]'s four keys,
// the top-level model_provider and, with Force, the reserved
// [model_providers.openai] table) and keeps every comment, key order and
// blank line it does not touch. It takes the same settings-file lock the
// undo and Observer's own codex hook / MCP writers take, keeps the file's
// mode and writes through a unique temp file beside it. An edit the line
// editor cannot express (our provider defined inline or inside an array of
// tables) is refused rather than re-serializing the operator's file.
func (r *Registrar) writeCodexAt(dir, want, toolLabel string) RegistrationResult {
	path := filepath.Join(dir, "config.toml")
	res := RegistrationResult{
		Tool:       toolLabel,
		ConfigPath: path,
		BaseURL:    want,
		DryRun:     r.opts.DryRun,
	}

	if r.opts.Lock != nil && !r.opts.DryRun {
		unlock, lerr := r.opts.Lock(path)
		if lerr != nil {
			res.Error = fmt.Errorf("proxyroute.codex: lock: %w", lerr)
			return res
		}
		defer unlock()
	}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("proxyroute.codex: read: %w", err)
		return res
	}
	doc, err := cfgfmt.ParseWith(cfgfmt.FormatTOML, raw, cfgfmt.Options{ForbidReserialize: true})
	if err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: parse %s: %w", path, err)
		return res
	}
	root, err := doc.Value()
	if err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: parse %s: %w", path, err)
		return res
	}

	providers, _ := root["model_providers"].(map[string]any)
	ops := []codexEdit{}

	// Codex 0.128.0+ rejects [model_providers.openai] outright. If we
	// silently leave it, codex won't load any of our changes either.
	if _, hasReserved := providers["openai"]; hasReserved {
		if !r.opts.Force {
			res.Error = fmt.Errorf(
				"proxyroute.codex: %s contains [model_providers.openai] which codex 0.128.0+ rejects (reserved built-in); pass --force to remove it",
				path,
			)
			return res
		}
		ops = append(ops, codexEdit{path: cfgfmt.Path{"model_providers", "openai"}, del: true})
	}

	ours, _ := providers[ProviderName].(map[string]any)

	if existing, ok := ours["base_url"].(string); ok && existing != "" {
		switch {
		case existing == want:
			// Provider block matches. Verify model_provider is also
			// pointed at us; only then is the registration AlreadySet.
			if mp, _ := root["model_provider"].(string); mp == ProviderName {
				res.AlreadySet = true
				res.BaseURL = existing
				return res
			}
			// Else fall through and set the top-level switch.
		case proxyauth.SameRoute(existing, want):
			// This route in the other form (plain vs client token):
			// rewrite it to the form this registrar writes.
		case IsObserverBaseURL(existing) && !r.opts.Force:
			res.AlreadySet = true
			res.BaseURL = existing
			return res
		case !r.opts.Force:
			res.Error = fmt.Errorf(
				"proxyroute.codex: model_providers.%s.base_url already set to %q; pass --force to overwrite",
				ProviderName, existing,
			)
			return res
		}
	}

	// Refuse to clobber a third-party model_provider unless forced.
	if mp, _ := root["model_provider"].(string); mp != "" && mp != ProviderName && !r.opts.Force {
		res.Error = fmt.Errorf(
			"proxyroute.codex: top-level model_provider is set to %q; pass --force to switch to %q",
			mp, ProviderName,
		)
		return res
	}

	if mp, _ := root["model_provider"].(string); mp != ProviderName {
		res.PriorProvider = mp
	}
	block := map[string]any{
		"name":                 providerDisplayName,
		"base_url":             want,
		"wire_api":             "responses",
		"requires_openai_auth": true,
	}
	if ours == nil {
		// No provider table yet: add it whole, as one [model_providers.
		// openai-observer] section.
		ops = append(ops, codexEdit{path: cfgfmt.Path{"model_providers", ProviderName}, value: block})
	} else {
		// Keep the operator's other keys in our table; set only ours.
		for _, k := range []string{"name", "base_url", "wire_api", "requires_openai_auth"} {
			ops = append(ops, codexEdit{path: cfgfmt.Path{"model_providers", ProviderName, k}, value: block[k]})
		}
	}
	ops = append(ops, codexEdit{path: cfgfmt.Path{"model_provider"}, value: ProviderName})

	for _, op := range ops {
		if err := op.apply(doc); err != nil {
			res.Error = fmt.Errorf("proxyroute.codex: edit %s in %s: %w", op.path, path, err)
			return res
		}
	}
	if r.opts.DryRun {
		res.Added = true
		return res
	}
	if err := guardWrite(dir, path); err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: %w", err)
		return res
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: mkdir: %w", err)
		return res
	}
	if err := writeFileKeepMode(path, doc.Bytes()); err != nil {
		res.Error = fmt.Errorf("proxyroute.codex: write: %w", err)
		return res
	}
	res.Added = true
	return res
}

// codexEdit is one surgical change writeCodexAt makes.
type codexEdit struct {
	path  cfgfmt.Path
	value any
	del   bool
}

func (e codexEdit) apply(doc cfgfmt.Doc) error {
	if e.del {
		return deleteTOMLKey(doc, e.path)
	}
	return doc.Set(e.path, e.value)
}

// deleteTOMLKey deletes path from doc surgically. When path is the only key
// of its parent table, the parent goes too: a parent that is only implied by
// its [parent.child] headers has no line of its own, so removing its last
// child is the removal of the parent (deleting just the child would leave an
// empty table the line editor cannot express, and an empty
// [model_providers] is noise in the operator's file anyway).
func deleteTOMLKey(doc cfgfmt.Doc, path cfgfmt.Path) error {
	if len(path) > 1 {
		parent := append(cfgfmt.Path(nil), path[:len(path)-1]...)
		v, found, err := doc.Get(parent)
		if err != nil {
			return err
		}
		if m, ok := v.(map[string]any); found && ok && len(m) == 1 {
			if _, only := m[path[len(path)-1]]; only {
				return deleteTOMLKey(doc, parent)
			}
		}
	}
	_, err := doc.Delete(path)
	return err
}

// CodexHint returns the human-readable, no-mutation guidance string for
// pointing codex at the observer proxy. Caller picks where to print.
func CodexHint(port int) string {
	url := codexBaseURL(port)
	var b strings.Builder
	fmt.Fprintln(&b, "next: route Codex through the observer proxy for accurate token capture.")
	fmt.Fprintln(&b, "  start the proxy:    observer proxy start")
	fmt.Fprintln(&b, "  add to ~/.codex/config.toml:")
	fmt.Fprintf(&b, "      model_provider = %q\n", ProviderName)
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "      [model_providers.%s]\n", ProviderName)
	fmt.Fprintf(&b, "      name = %q\n", providerDisplayName)
	fmt.Fprintf(&b, "      base_url = %q\n", url)
	fmt.Fprintln(&b, "      wire_api = \"responses\"")
	fmt.Fprintln(&b, "      requires_openai_auth = true")
	fmt.Fprintln(&b, "  why a custom provider name: codex 0.128.0+ rejects [model_providers.openai].")
	return b.String()
}
