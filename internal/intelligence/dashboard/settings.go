package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/routing"
)

// handleConfig serves GET /api/config — the full live config struct
// rendered to JSON. Settings UI uses this to populate every section's
// form (or read-only display); the Pricing edit path POSTs back via
// /api/config/pricing.
//
// The response includes the resolved config_path so the UI can show
// which file would be written on save and surface a clear "no path —
// running ephemeral" state.
//
// T2 credentials are REDACTED before marshalling (plan §4.3 / P0-1):
// [selfobs].secret, [selfobs].token, [observer.process.etw].token and
// [routing].key_pool come back as secretSentinel, with redacted_secrets
// reporting per-key whether a value is configured. See config_secrets.go.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	redacted, secretsPresent := redactSecrets(cfg)
	// Optimistic-concurrency base for PUT /api/config/keys (plan §2.4): the
	// hash of the file bytes as they are NOW. A hand-edit, a CLI write or a
	// concurrent dashboard save all change it, so a stale form gets a 409
	// naming the diverged keys instead of silently clobbering.
	etag, err := configEtag(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"config_path": s.opts.ConfigPath,
		"config":      redacted,
		"config_etag": etag,
		// The sensitive-tier (T1) keys need the same confirm-token
		// double-submit the remote arm verbs use; minted (or reused) here so
		// the schema-driven form can save them without a second round trip.
		"confirm_token":  setConfirmCookie(w, r),
		"schema_version": configschema.SchemaVersion,
		// Dotted path → whether a credential is configured there. The
		// value itself never leaves the daemon; the UI renders a
		// read-only "credential configured" state from this instead.
		"redacted_secrets": secretsPresent,
		// The exact placeholder substituted above, so the UI can detect
		// it without hardcoding the string.
		"redacted_sentinel": secretSentinel,
		// Every resolvable compression profile (built-ins + user
		// profiles, P3.4) — the Settings Profiles panel's dynamic
		// option source.
		"profile_names": config.ProfileStore{Dir: config.DefaultProfilesDir(s.opts.ConfigPath)}.Names(),
		// Capabilities — every section the UI may edit. "pricing" hot-reloads
		// the cost engine in place (no restart). The rest write to disk and
		// require a daemon restart to take effect; the UI surfaces a
		// "Restart daemon" banner after each non-pricing save.
		"editable_sections": []string{
			"pricing", "observer", "watcher", "freshness", "retention",
			"hooks", "proxy", "dashboard", "compression", "intelligence",
			"advisor", "cachetrack", "observability", "secrets", "profiles", "mcp",
			"org", "otel", "guard", "routing", "process", "browser", "terminal", "tasks",
		},
	})
}

// handleConfigPricing serves PUT /api/config/pricing — accepts the
// `intelligence.pricing.models` map and writes it back to config.toml.
// Reloads the cost engine in-place so Cost / Analysis / Session-detail
// surfaces pick up the new rates without a restart.
//
// Save flow:
//  1. Resolve config path (errors if not configured)
//  2. Load current config from disk
//  3. Replace cfg.Intelligence.Pricing.Models with the request body
//  4. Copy current config.toml → config.toml.bak (Option A — comments
//     lost on save, .bak preserves the prior version)
//  5. Marshal full struct to TOML, atomic temp-file rename
//  6. cost.Engine.Reload(cfg.Intelligence) — atomic.Pointer swap
//
// On any error before step 4, no files are touched. On error during 4–5,
// the .bak preserves the user's prior file.
func (s *Server) handleConfigPricing(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.writeEffectivePricing(r.Context(), w)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured — server has no file to save to", http.StatusConflict)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		Models map[string]config.ModelPricing `json:"models"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Models == nil {
		req.Models = map[string]config.ModelPricing{}
	}

	// Same serialization as the section-save path (Fix 1): pricing does the
	// same load→patch→write against the shared file, so it must take the same
	// lock or a concurrent section save could clobber the pricing write (or
	// vice-versa). See Server.configWriteMu.
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()

	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
	if err != nil {
		writeErr(w, fmt.Errorf("load current config: %w", err))
		return
	}
	cfg.Intelligence.Pricing.Models = req.Models

	if err := writeConfigToml(s.opts.ConfigPath, cfg); err != nil {
		writeErr(w, err)
		return
	}

	if s.opts.CostEngine != nil {
		s.opts.CostEngine.Reload(cfg.Intelligence)
	}
	s.notifyConfigSaved()

	resp := map[string]any{
		"saved":       true,
		"config_path": s.opts.ConfigPath,
		"backup_path": s.opts.ConfigPath + ".bak",
		"models":      cfg.Intelligence.Pricing.Models,
	}
	// Advisory problems found while rebuilding the table — a malformed
	// [intelligence.pricing.dated] row that was SKIPPED, or a dated
	// timeline whose newest entry no longer matches the flat rate the
	// operator just saved (a half-landed rate change: history would be
	// right but today's costs wrong). Pricing never fails closed on
	// these, so the save still succeeded; surfacing them is how the
	// operator finds out their override was ignored.
	if s.opts.CostEngine != nil {
		if warn := s.opts.CostEngine.PricingWarnings(); len(warn) > 0 {
			resp["warnings"] = warn
		}
	}
	writeJSON(w, resp)
}

// notifyConfigSaved invokes the daemon's config-saved hook (P2.5 hot
// reload) after a successful config.toml write. No-op when unwired
// (tests, read-only dashboards, `observer dashboard` standalone).
func (s *Server) notifyConfigSaved() {
	if s.opts.OnConfigSaved != nil {
		s.opts.OnConfigSaved()
	}
}

// handleConfigReload serves POST /api/config/reload — fires the same
// config-saved hook the dashboard's own save paths fire, for writers
// OUTSIDE this process: `observer profile assign` and hand-edits to
// config.toml use it to make a running daemon re-read [profiles] and
// compression parameters (new sessions only; the P2.5 contract). The
// response reports whether a hook is actually wired so callers can
// tell "reloaded" from "nothing listening" (standalone dashboards
// have no proxy router to poke).
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	wired := s.opts.OnConfigSaved != nil
	s.notifyConfigSaved()
	writeJSON(w, map[string]any{
		"reloaded": wired,
		"wired":    wired,
	})
}

// writeEffectivePricing serves GET /api/config/pricing — the EFFECTIVE price
// table this node is actually using, one row per model, each labelled with
// where its rate came from (pricing arc §3.3).
//
// WHY THIS EXISTS AT ALL. Before this arc the Settings page could show a
// developer their own [intelligence.pricing] overrides and the baked-in
// defaults, and that was the whole truth. It no longer is: an org can now
// distribute negotiated rates that sit UNDER those overrides on an individual
// node and OVER them on a managed one, so "what does this machine think a
// token costs" stopped being answerable from the config file. A surface that
// showed only the two local halves would be quietly wrong on exactly the
// installs where the answer matters.
//
// The `source` per row is therefore the point of the endpoint, not a
// decoration: it is `org` for a rate the org supplied, `local` for one this
// developer typed, and `seed` for the compiled default. It comes from the
// ENGINE's own lookup (cost.PricingSourceOrg), so it cannot drift from what
// the proxy will actually stamp onto the next turn.
func (s *Server) writeEffectivePricing(ctx context.Context, w http.ResponseWriter) {
	engine := s.opts.CostEngine
	if engine == nil {
		// No engine wired (a dashboard assembled without one). An empty
		// table with the reason is honest; inventing the seed table here
		// would claim rates this process is not using.
		writeJSON(w, map[string]any{
			"models":    map[string]any{},
			"available": false,
			"reason":    "this dashboard was assembled without a cost engine, so it cannot report effective rates",
		})
		return
	}
	feed := s.feedPosture(ctx)
	type pricedModel struct {
		cost.Pricing
		// Source is seed | local | org | feed. It is the ONE field a caller
		// needs that the rate itself cannot carry. `feed` is the standalone
		// public-feed case (§G): the engine reports it as org (same input),
		// relabelled here when the feed is this node's active org-shaped source.
		Source string `json:"source"`
		// Economics is the optional per-model economics the feed carried
		// (cache mode / reasoning billing, §K). Present only for a feed model
		// that declared it; nil otherwise (unknown, never a fabricated default).
		Economics *dashboardFeedEconomics `json:"economics,omitempty"`
	}
	out := map[string]pricedModel{}
	table := engine.Table()
	if table != nil {
		for _, model := range table.Known() {
			p, src, ok := engine.LookupWithSource(model)
			if !ok {
				continue
			}
			pm := pricedModel{Pricing: p, Source: effectivePricingSource(src, feed.Active)}
			if pm.Source == "feed" {
				if e, hit := feed.Economics[model]; hit {
					ec := e
					pm.Economics = &ec
				}
			}
			out[model] = pm
		}
	}
	payload := map[string]any{
		"models":    out,
		"available": true,
		// The org half, reported even when zero so a surface can say "no org
		// pricing is applied" rather than leaving the reader to infer it from
		// an absence of org-sourced rows.
		"org_version":       engine.OrgPricingVersion(),
		"org_authoritative": engine.OrgPricingAuthoritative(),
		"warnings":          engine.PricingWarnings(),
	}
	if feed.Active {
		// The standalone public-feed half (§G). Present only when the feed is
		// the active org-shaped source, so a surface renders nothing when the
		// feed is off or the node is enrolled.
		payload["feed_version"] = feed.Version
		payload["feed_fetched_at"] = feed.FetchedAt
		payload["feed_state"] = feed.State
	}
	writeJSON(w, payload)
}

// effectivePricingSource collapses the engine's resolution vocabulary onto the
// PROVENANCE vocabulary this endpoint reports: seed | local | org | feed.
//
// exact / date-stripped / family all collapse to `seed`: the difference
// between them is about how confidently the SKU was identified, which the
// Settings page already surfaces elsewhere, whereas the question THIS endpoint
// answers is whose rate it is. The engine distinguishes an org rate from a
// developer's own override; `feed` is the standalone public-feed case, which
// the engine composes as `org` (same input) and which is relabelled here when
// feedActive — an enrolled node never reaches this branch because it ignores
// the feed (§C.3/D8).
func effectivePricingSource(src cost.PricingSource, feedActive bool) string {
	switch src {
	case cost.PricingSourceOrg:
		if feedActive {
			return "feed"
		}
		return "org"
	case cost.PricingSourceLocal:
		return "local"
	default:
		return "seed"
	}
}

// handleConfigPricingDefaults serves GET /api/config/pricing/defaults
// — the cost engine's baked-in pricing table as { model_id: Pricing }.
// Used by the Settings → Pricing form to render a defaults reference
// list and the "override this default" shortcut.
func (s *Server) handleConfigPricingDefaults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"defaults": cost.BakedInDefaults(),
		// The baked-in HISTORICAL rate timelines, keyed like `defaults`.
		// Empty on a stock build. Present so this endpoint can never
		// imply a model has had exactly one rate for all time when the
		// cost engine is in fact splitting its history — see
		// internal/intelligence/cost/dated.go.
		"dated_defaults": cost.BakedInDatedDefaults(),
	})
}

// handleConfigSection serves PUT /api/config/section/<name> — the
// generic save path for every config section other than pricing
// (which has its own hot-reload-aware endpoint). Slice 2 of the
// Settings page wires this for: observer, watcher, freshness,
// retention, hooks, proxy, compression, intelligence.
//
// Save flow mirrors handleConfigPricing:
//  1. Resolve config path; require non-empty.
//  2. Load current config.
//  3. Replace the named section's fields with the request body.
//  4. writeConfigToml — backs up to .bak then atomic rename.
//  5. Response sets restart_required=true so the UI surfaces the
//     "Restart daemon" banner. Pricing's hot-reload doesn't apply
//     because the affected consumers (proxy listener, watcher
//     subscriptions, hook registrations, retention prune cycle, etc.)
//     bind config at startup. Exception: "profiles" reports
//     restart_required=false — the OnConfigSaved hook hot-reloads the
//     proxy's profile router for new sessions (P2.5).
func (s *Server) handleConfigSection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "PUT only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured — server has no file to save to", http.StatusConflict)
		return
	}

	// Path is /api/config/section/<name>; strip the prefix.
	name := strings.TrimPrefix(r.URL.Path, "/api/config/section/")
	if name == "" || strings.Contains(name, "/") {
		http.Error(w, "section name required (e.g. /api/config/section/observer)", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Serialize the whole load→patch→validate→write critical section against
	// every other config-file writer (Fix 1): a concurrent PUT to a DIFFERENT
	// section must not lose this one's change. See Server.configWriteMu.
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()

	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load current config: %w", err))
		return
	}

	// Deep snapshot of the pre-update config so restart_required can be
	// derived per CHANGED KEY from the schema's restart classes (plan §3.1 /
	// P0-8) instead of a per-section heuristic. The per-field rules that
	// used to live here — terminal.attach.enabled binds the socket at start
	// while route_proxy / default_on are read per launch; only [cloud]'s
	// auto_sync schedule binds at start while base_url / auto_enrich /
	// workos_client_id are read by each `observer cloud` invocation — are
	// now rows in internal/configschema/annotations.go.
	prev := cloneConfig(cfg)

	// Snapshot the T2 credentials before the update so the guard below can
	// tell "unchanged" from "the caller echoed a sentinel back" from "the
	// caller tried to write a credential".
	prevSecrets := secretsSnapshot(&cfg)

	if err := applySectionUpdate(&cfg, name, body, s.opts.ConfigPath); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// T2 credential guard (plan §4.3 / P0-1). Two failure modes it closes,
	// in the one place every caller-supplied section body lands:
	//   1. A write attempt on a credential is refused with 403 naming the
	//      file — credentials are file-only, by design.
	//   2. A round-trip clobber. GET /api/config now returns sentinels, and
	//      several callers read a whole section and PUT it back verbatim
	//      (Routing.tsx enableAdvise, Settings.tsx); without this, that
	//      would overwrite a real API key with "__redacted__". An incoming
	//      sentinel restores the on-disk value instead.
	if err := reconcileSecrets(&cfg, &prevSecrets, s.opts.ConfigPath); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Validate-before-write: run the SAME semantic check config.Load runs at
	// daemon start, so a section save can never persist a config the next
	// start would reject (the bricked-restart class — e.g. a garbage
	// [dashboard].addr). cfg came from a successful loadConfigForDashboard, so
	// it was already valid; this only catches invalidity introduced by THIS
	// PUT body. Generic on purpose — closes the gap for every section, not
	// just the one that surfaced it.
	if err := config.Validate(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := writeConfigToml(s.opts.ConfigPath, cfg); err != nil {
		writeErr(w, err)
		return
	}
	s.notifyConfigSaved()

	// Profiles hot-reload (P2.5): the config-saved hook re-points the
	// proxy's profile router, so NEW sessions pick the change up with
	// no restart. MCP (P4.10) is the other no-banner section: each AI
	// session spawns a fresh `observer serve` subprocess that runs
	// config.Load itself, so saves bind on the next MCP spawn with no
	// daemon restart — the banner would lie for both.
	//
	// Restart honesty (plan §3.1 / P0-8): classify every key this save
	// actually CHANGED by its schema restart class. The per-section
	// heuristic that used to live here (`name != "profiles" && name !=
	// "mcp"` plus hand-coded terminal and cloud exceptions) is retired: at
	// 500 keys a heuristic cannot stay true, the table can.
	changed := configschema.ChangedLeaves(&prev, &cfg)
	classes := classifyChanged(changed, nil)
	writeJSON(w, map[string]any{
		"saved":                 true,
		"section":               name,
		"config_path":           s.opts.ConfigPath,
		"backup_path":           s.opts.ConfigPath + ".bak",
		"restart_required":      len(classes.restart) > 0,
		"changed_keys":          orEmptyStrings(changed),
		"restart_required_keys": orEmptyStrings(classes.restart),
		"applied_live_keys":     orEmptyStrings(classes.live),
		"next_spawn_keys":       orEmptyStrings(classes.nextSpawn),
	})
}

// applySectionUpdate decodes body as the named section's payload and
// writes it onto cfg. Section names map to either a top-level Config
// field, a nested ObserverConfig sub-struct, or a synthetic group of
// scalar Observer / Intelligence fields. Pricing is intentionally
// unhandled — that section has a dedicated endpoint with hot-reload.
//
//nolint:gocyclo // one case per settings section by design; complexity grows with the section list, not logic depth (P6 arc).
func applySectionUpdate(cfg *config.Config, name string, body []byte, configPath string) error {
	switch name {
	case "observer":
		// Top-level Observer scalars only. Nested sub-structs (Watch,
		// Freshness, Retention, Hooks) are exposed as their own
		// sections so saving "observer" doesn't clobber values the
		// user is editing in the watcher or retention pane.
		var sec struct {
			DBPath   string `json:"DBPath"`
			LogLevel string `json:"LogLevel"`
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode observer section: %w", err)
		}
		cfg.Observer.DBPath = sec.DBPath
		cfg.Observer.LogLevel = sec.LogLevel
	case "watcher":
		var sec config.WatchConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode watcher: %w", err)
		}
		cfg.Observer.Watch = sec
	case "freshness":
		var sec config.FreshnessConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode freshness: %w", err)
		}
		cfg.Observer.Freshness = sec
	case "retention":
		var sec config.RetentionConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode retention: %w", err)
		}
		cfg.Observer.Retention = sec
	case "hooks":
		var sec config.HooksConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode hooks: %w", err)
		}
		cfg.Observer.Hooks = sec
	case "antigravity":
		var sec config.AntigravityConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode antigravity: %w", err)
		}
		cfg.Observer.Antigravity = sec
	case "cloud":
		// Editable subset of [cloud] (Settings → Cloud Intelligence's "Cloud
		// settings" card): base URL, the two automation toggles + interval, and
		// the PUBLIC WorkOS client id. LoginPort keeps its loaded value (it must
		// match a WorkOS-registered redirect URI, a hand-written decision).
		// Pointer fields so a partial body preserves what it omits (the
		// process-section idiom); config.Validate re-checks base_url shape and
		// the interval floor before the write.
		var sec struct {
			BaseURL                 *string `json:"BaseURL"`
			AutoSync                *bool   `json:"AutoSync"`
			AutoSyncIntervalMinutes *int    `json:"AutoSyncIntervalMinutes"`
			AutoEnrich              *bool   `json:"AutoEnrich"`
			WorkOSClientID          *string `json:"WorkOSClientID"`
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode cloud: %w", err)
		}
		if sec.BaseURL != nil {
			cfg.Cloud.BaseURL = strings.TrimSpace(*sec.BaseURL)
		}
		if sec.AutoSync != nil {
			cfg.Cloud.AutoSync = *sec.AutoSync
		}
		if sec.AutoSyncIntervalMinutes != nil {
			cfg.Cloud.AutoSyncIntervalMinutes = *sec.AutoSyncIntervalMinutes
		}
		if sec.AutoEnrich != nil {
			cfg.Cloud.AutoEnrich = *sec.AutoEnrich
		}
		if sec.WorkOSClientID != nil {
			cfg.Cloud.WorkOSClientID = strings.TrimSpace(*sec.WorkOSClientID)
		}
	case "browser":
		// Editable subset of [browser]: the daemon's granularity ceiling
		// (the §5.1 clamp — the maximum stored granularity regardless of
		// what the extension sends). Other [browser] fields (rail toggles,
		// listener addr) keep their loaded values. config.Validate rejects
		// a ceiling outside {usage_only, redacted, full} before write.
		var sec struct {
			GranularityCeiling string `json:"GranularityCeiling"`
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode browser: %w", err)
		}
		cfg.Browser.GranularityCeiling = sec.GranularityCeiling
	case "process":
		// Editable subset of [observer.process]: the capture toggle, backend,
		// the unified poll cadence, and the bridge override. The scrub/argv/env
		// sub-sections keep their loaded values (the Settings pane edits only
		// these operator-facing scalars; sub-struct edits would need their own
		// panes, mirroring the watcher/retention split above).
		//
		// POINTER fields (F3): every scalar is a pointer so a PARTIAL body
		// preserves the fields it omits instead of zeroing them. Decoding plain
		// value scalars made a partial {"Enabled":true} also blank Backend to ""
		// (rejected by the vocabulary check) and reset the intervals to 0 —
		// forcing the FE into a racy read-then-write and silently overwriting
		// Backend. nil ⇒ keep the loaded value; assign (and validate) only the
		// fields the caller actually sent. The FE full-body send (all fields
		// present) still applies every field, so behaviour there is unchanged.
		// Mirrors the terminal section's pointer idiom + the Network sub-struct's
		// existing only-when-non-nil application.
		var sec struct {
			Enabled              *bool   `json:"Enabled"`
			Backend              *string `json:"Backend"`
			CaptureUnattributed  *bool   `json:"CaptureUnattributed"`
			PollIntervalMS       *int    `json:"PollIntervalMS"`
			BridgePollIntervalMS *int    `json:"BridgePollIntervalMS"`
			Network              *struct {
				Enabled           *bool   `json:"Enabled"`
				CaptureRemoteHost *bool   `json:"CaptureRemoteHost"`
				RedactPrivateIPs  *bool   `json:"RedactPrivateIPs"`
				CaptureBodies     *string `json:"CaptureBodies"`
				MaxRequestBytes   *int    `json:"MaxRequestBytes"`
				MaxResponseBytes  *int    `json:"MaxResponseBytes"`
				CaptureHeaders    *bool   `json:"CaptureHeaders"`
				ScrubBodies       *bool   `json:"ScrubBodies"`
				StoreBinary       *bool   `json:"StoreBinary"`
			} `json:"Network"`
			// [observer.process.etw] — the daemon-side accept listener for the
			// elevated Windows ETW capturer. Same pointer idiom, so the ETW
			// card's one-field PUT ({"ETW":{"Enabled":true}}) preserves every
			// other key instead of zeroing the listener address and timeout.
			//
			// TOKEN IS DELIBERATELY ABSENT. It is a shared secret whose whole
			// job is to gate a loopback port that WSL2's localhostForwarding
			// exposes to every process on the Windows host. It has no editor
			// here, and — because this decoder has no field for it — a body
			// that carries one is IGNORED rather than round-tripped, so the
			// value in config.toml is what the operator put there. An operator
			// who wants to set one edits config.toml; empty (the default) means
			// the daemon generates and persists one at TokenPath.
			ETW *struct {
				Enabled            *bool   `json:"Enabled"`
				ListenAddr         *string `json:"ListenAddr"`
				AllowNonLoopback   *bool   `json:"AllowNonLoopback"`
				TokenPath          *string `json:"TokenPath"`
				HandshakeTimeoutMS *int    `json:"HandshakeTimeoutMS"`
			} `json:"ETW"`
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode process: %w", err)
		}
		// Validate only PROVIDED fields — an omitted (nil) field keeps its
		// already-valid loaded value.
		if sec.Backend != nil {
			switch *sec.Backend {
			case "auto", "bridge", "both", "linux_ebpf", "etw", "endpointsecurity", "poll", "off":
			default:
				return fmt.Errorf("process.backend %q not in {auto, bridge, both, linux_ebpf, etw, endpointsecurity, poll, off}", *sec.Backend)
			}
		}
		if sec.PollIntervalMS != nil && *sec.PollIntervalMS < 0 {
			return fmt.Errorf("process.poll_interval_ms must be >= 0 (0 inherits the 2000 ms default), got %d", *sec.PollIntervalMS)
		}
		if sec.BridgePollIntervalMS != nil && *sec.BridgePollIntervalMS < 0 {
			return fmt.Errorf("process.bridge_poll_interval_ms must be >= 0 (0 inherits poll_interval_ms), got %d", *sec.BridgePollIntervalMS)
		}
		if sec.Network != nil {
			if sec.Network.CaptureBodies != nil {
				switch *sec.Network.CaptureBodies {
				case "off", "proxied", "available":
				default:
					return fmt.Errorf("process.network.capture_bodies %q not in {off, proxied, available}", *sec.Network.CaptureBodies)
				}
			}
			if sec.Network.MaxRequestBytes != nil && *sec.Network.MaxRequestBytes < 0 {
				return fmt.Errorf("process.network.max_request_bytes must be >= 0, got %d", *sec.Network.MaxRequestBytes)
			}
			if sec.Network.MaxResponseBytes != nil && *sec.Network.MaxResponseBytes < 0 {
				return fmt.Errorf("process.network.max_response_bytes must be >= 0, got %d", *sec.Network.MaxResponseBytes)
			}
		}
		if sec.ETW != nil {
			// A malformed listen_addr does NOT fail config.Load — it fails
			// later, when the daemon tries to bind, by which time the operator
			// has restarted into a listener that never comes up. Catch it here
			// so the save is refused with the value that caused it.
			if sec.ETW.ListenAddr != nil && strings.TrimSpace(*sec.ETW.ListenAddr) != "" {
				if _, _, err := net.SplitHostPort(strings.TrimSpace(*sec.ETW.ListenAddr)); err != nil {
					return fmt.Errorf("process.etw.listen_addr %q is not a host:port address (%v) — "+
						"leave it empty to inherit the 127.0.0.1:8823 default", *sec.ETW.ListenAddr, err)
				}
			}
			if sec.ETW.HandshakeTimeoutMS != nil && *sec.ETW.HandshakeTimeoutMS < 0 {
				return fmt.Errorf("process.etw.handshake_timeout_ms must be >= 0 (0 inherits the 10000 ms default), got %d",
					*sec.ETW.HandshakeTimeoutMS)
			}
		}
		if sec.Enabled != nil {
			cfg.Observer.Process.Enabled = *sec.Enabled
		}
		if sec.Backend != nil {
			cfg.Observer.Process.Backend = *sec.Backend
		}
		if sec.CaptureUnattributed != nil {
			cfg.Observer.Process.CaptureUnattributed = *sec.CaptureUnattributed
		}
		if sec.PollIntervalMS != nil {
			cfg.Observer.Process.PollIntervalMS = *sec.PollIntervalMS
		}
		if sec.BridgePollIntervalMS != nil {
			cfg.Observer.Process.BridgePollIntervalMS = *sec.BridgePollIntervalMS
		}
		if sec.Network != nil {
			if sec.Network.Enabled != nil {
				cfg.Observer.Process.Network.Enabled = *sec.Network.Enabled
			}
			if sec.Network.CaptureRemoteHost != nil {
				cfg.Observer.Process.Network.CaptureRemoteHost = *sec.Network.CaptureRemoteHost
			}
			if sec.Network.RedactPrivateIPs != nil {
				cfg.Observer.Process.Network.RedactPrivateIPs = *sec.Network.RedactPrivateIPs
			}
			if sec.Network.CaptureBodies != nil {
				cfg.Observer.Process.Network.CaptureBodies = *sec.Network.CaptureBodies
			}
			if sec.Network.MaxRequestBytes != nil {
				cfg.Observer.Process.Network.MaxRequestBytes = *sec.Network.MaxRequestBytes
			}
			if sec.Network.MaxResponseBytes != nil {
				cfg.Observer.Process.Network.MaxResponseBytes = *sec.Network.MaxResponseBytes
			}
			if sec.Network.CaptureHeaders != nil {
				cfg.Observer.Process.Network.CaptureHeaders = *sec.Network.CaptureHeaders
			}
			if sec.Network.ScrubBodies != nil {
				cfg.Observer.Process.Network.ScrubBodies = *sec.Network.ScrubBodies
			}
			if sec.Network.StoreBinary != nil {
				cfg.Observer.Process.Network.StoreBinary = *sec.Network.StoreBinary
			}
		}
		if sec.ETW != nil {
			if sec.ETW.Enabled != nil {
				cfg.Observer.Process.ETW.Enabled = *sec.ETW.Enabled
			}
			if sec.ETW.ListenAddr != nil {
				cfg.Observer.Process.ETW.ListenAddr = strings.TrimSpace(*sec.ETW.ListenAddr)
			}
			if sec.ETW.AllowNonLoopback != nil {
				cfg.Observer.Process.ETW.AllowNonLoopback = *sec.ETW.AllowNonLoopback
			}
			if sec.ETW.TokenPath != nil {
				cfg.Observer.Process.ETW.TokenPath = strings.TrimSpace(*sec.ETW.TokenPath)
			}
			if sec.ETW.HandshakeTimeoutMS != nil {
				cfg.Observer.Process.ETW.HandshakeTimeoutMS = *sec.ETW.HandshakeTimeoutMS
			}
			// Token is intentionally not assigned — see the decoder above.
		}
	case "terminal":
		// Editable subset of [terminal.attach] (session-attach design Phase 4,
		// §6 decisions #1/#7). Writes ONLY Attach.Enabled + Attach.RouteProxy;
		// every other [terminal] sub-struct (Launch, Status, the bounds scalars)
		// keeps its loaded value — the same selective-copy discipline the process
		// section uses. The FE section path is ["Terminal","Attach"], so the PUT
		// body IS the Attach sub-object.
		//
		// POINTER fields (F5): a partial body must PRESERVE the omitted field, not
		// silently reset it to false. Decoding plain bools made {"RouteProxy":false}
		// also disable Attach.Enabled (and vice-versa); nil ⇒ keep the loaded value,
		// assign only the fields the caller actually sent. The FE form always sends
		// all three, so this only tightens partial/programmatic callers.
		var sec struct {
			Enabled    *bool `json:"Enabled"`
			RouteProxy *bool `json:"RouteProxy"`
			DefaultOn  *bool `json:"DefaultOn"`
		}
		// F4: strict-decode (DisallowUnknownFields) AND require at least one known
		// field. Plain json.Unmarshal silently ignores unknown keys, so a typo
		// like {"RouteProxi":false} decoded to nil pointers and reported
		// saved=true while writing the UNCHANGED config — telling the caller a
		// setting was saved that never was. Reject an unknown field and an
		// all-omitted body with a 400 (applySectionUpdate errors → 400 in the
		// caller) that names the accepted fields.
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&sec); err != nil {
			return fmt.Errorf("decode terminal: %w (accepted fields: Enabled, RouteProxy, DefaultOn)", err)
		}
		// A streaming Decoder reads exactly ONE JSON value, so a body like
		// {"Enabled":true}{"RouteProxi":false} would decode the first object and
		// silently ignore the trailing garbage — reporting saved=true while the
		// caller's real (typo'd) intent was dropped. Require the stream to be at
		// EOF after the object; any trailing value ⇒ 400 (caller maps to 400).
		// Keep this the LAST decode step (bdb057c0).
		if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
			return fmt.Errorf("decode terminal: unexpected trailing content after the JSON object (accepted fields: Enabled, RouteProxy, DefaultOn)")
		}
		if sec.Enabled == nil && sec.RouteProxy == nil && sec.DefaultOn == nil {
			return fmt.Errorf("terminal section requires at least one known field (accepted: Enabled, RouteProxy, DefaultOn)")
		}
		if sec.Enabled != nil {
			cfg.Terminal.Attach.Enabled = *sec.Enabled
		}
		if sec.RouteProxy != nil {
			cfg.Terminal.Attach.RouteProxy = *sec.RouteProxy
		}
		if sec.DefaultOn != nil {
			cfg.Terminal.Attach.DefaultOn = *sec.DefaultOn
		}
	case "proxy":
		var sec config.ProxyConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode proxy: %w", err)
		}
		cfg.Proxy = sec
	case "dashboard":
		var sec config.DashboardConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode dashboard: %w", err)
		}
		cfg.Dashboard = sec
	case "compression":
		var sec config.CompressionConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode compression: %w", err)
		}
		cfg.Compression = sec
	case "intelligence":
		// Pricing has its own endpoint with hot-reload, so don't let
		// this save path clobber it. Decode the editable subset, then
		// restore Pricing from the prior cfg.
		var sec struct {
			CodeGraph        config.IntelligenceCodeGraphConfig `json:"CodeGraph"` //nolint:staticcheck // SA1019: intentional — decode the legacy [intelligence.code_graph] block during the one-release migration window (docs/codeintel/migration-from-codegraph.md).
			APIKeyEnv        string                             `json:"APIKeyEnv"`
			SummaryModel     string                             `json:"SummaryModel"`
			MonthlyBudgetUSD float64                            `json:"MonthlyBudgetUSD"`
			// Pointer so absence is distinguishable from empty: the
			// Settings intelligence form doesn't carry the budget map,
			// and a nil here must PRESERVE the stored budgets (the D14
			// save-zeroing class). The Cost page's Budget card always
			// sends the field — including an explicit {} to clear.
			ProjectBudgetsUSD *map[string]float64 `json:"ProjectBudgetsUSD"`
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode intelligence: %w", err)
		}
		cfg.Intelligence.CodeGraph = sec.CodeGraph
		cfg.Intelligence.APIKeyEnv = sec.APIKeyEnv
		cfg.Intelligence.SummaryModel = sec.SummaryModel
		cfg.Intelligence.MonthlyBudgetUSD = sec.MonthlyBudgetUSD
		if sec.ProjectBudgetsUSD != nil {
			cfg.Intelligence.ProjectBudgetsUSD = *sec.ProjectBudgetsUSD
		}
		// Pricing intentionally untouched.
	case "advisor":
		var sec config.AdvisorConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode advisor: %w", err)
		}
		cfg.Advisor = sec
	case "cachetrack":
		var sec config.CacheTrackConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode cachetrack: %w", err)
		}
		cfg.CacheTrack = sec
	case "tasks":
		// [tasks] session-level task/todo/plan checklist tracking
		// (docs/task-tracking.md). Settings → Tasks panel ships
		// (web/src/pages/settings/sectionSpecs.ts's "tasks" entry) on
		// top of this generic round-trip, same shape as "cachetrack".
		var sec config.TasksConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode tasks: %w", err)
		}
		cfg.Tasks = sec
	case "observability":
		// The [observability] subsystem on/off gate (internal/obs): the
		// OTLP /v1/traces receiver, the obs_* schema, trajectory
		// ingestion + API, and the eval plane.
		//
		// Three surfaces write this section, so every field is a POINTER
		// and only the fields actually sent are applied (the terminal /
		// process partial-merge discipline). This is REQUIRED, not a nicety:
		// the Settings toggle sends {Enabled}, the Policies module's judge
		// form sends {Judge}, and its budget form sends {Admission:{Budget}} —
		// a plain-bool Enabled would decode to false and DISABLE the whole
		// subsystem whenever the Policies form (which omits Enabled) saved.
		//
		// The shared judge binding ([observability.judge]), the admission
		// judge override ([observability.admission.judge]), and the
		// per-end-user budget ([observability.admission.budget]) are edited by
		// the Policies module (judge + budget are read at daemon start, not
		// hot-swappable, so this restart-oriented section save is their apply
		// path — docs/handovers/policies-module-phase-b-handover-2026-08-04.md
		// §5). Everything else under [observability] is preserved wholesale:
		// Eval (hand-written judge-model selection), the admission criterion
		// table + mode/scope/prefilter (owned by the admission POLICY persister
		// cmd/observer/admission_persist.go — never this seam, CLAUDE.md #4),
		// Egress, and Alerts.
		var sec struct {
			Enabled   *bool                            `json:"Enabled"`
			Judge     *config.ObservabilityJudgeConfig `json:"Judge"`
			Admission *struct {
				Budget *config.AdmissionBudgetConfig    `json:"Budget"`
				Judge  *config.ObservabilityJudgeConfig `json:"Judge"`
			} `json:"Admission"`
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode observability: %w", err)
		}
		if sec.Enabled != nil {
			cfg.Observability.Enabled = *sec.Enabled
		}
		if sec.Judge != nil {
			if sec.Judge.TimeoutMS < 0 || sec.Judge.MaxTokens < 0 || sec.Judge.NumCtx < 0 {
				return fmt.Errorf("observability judge: timeout_ms/max_tokens/num_ctx must be >= 0")
			}
			cfg.Observability.Judge = *sec.Judge
		}
		if sec.Admission != nil {
			if sec.Admission.Budget != nil {
				b := sec.Admission.Budget
				if b.PerUser5hUSD < 0 || b.PerUserWeeklyUSD < 0 || b.PerUserMonthlyUSD < 0 {
					return fmt.Errorf("observability admission budget: per-user caps must be >= 0")
				}
				cfg.Observability.Admission.Budget = *b
			}
			if sec.Admission.Judge != nil {
				if sec.Admission.Judge.TimeoutMS < 0 || sec.Admission.Judge.MaxTokens < 0 || sec.Admission.Judge.NumCtx < 0 {
					return fmt.Errorf("observability admission judge: timeout_ms/max_tokens/num_ctx must be >= 0")
				}
				cfg.Observability.Admission.Judge = *sec.Admission.Judge
			}
		}
	case "secrets":
		// Nested under [observer.secrets] in TOML but surfaced as its
		// own section so the privacy-relevant scrubbing controls don't
		// hide behind the top-level observer scalars.
		var sec config.SecretsConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode secrets: %w", err)
		}
		cfg.Observer.Secrets = sec
	case "mcp":
		// Nested under [intelligence.mcp] in TOML but surfaced as its
		// own section (P4.10 / review row A4): the V7-12 retrieval
		// tools + audit knobs. Consumed by the per-AI-tool `observer
		// serve` subprocess at spawn, not by this daemon.
		var sec config.IntelligenceMCPConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode mcp: %w", err)
		}
		cfg.Intelligence.MCP = sec
	case "org":
		// Org sharing posture (P4.12 / review row A5): share-mode +
		// scope lists + push cadence ONLY. The enrolment identity
		// fields (Enabled, OrgServerURL, KeychainID) are deliberately
		// NOT copied — they're written by `observer enroll`/`unenroll`
		// alongside keychain state, and a section save must never be
		// able to detach or re-point an enrolment (the same selective
		// copy the intelligence case uses for pricing). The share knobs
		// stay node-side opt-in: no server, and no dashboard serving a
		// different node, can flip them — this PUT only ever writes
		// THIS node's config file.
		var sec config.OrgClientConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode org: %w", err)
		}
		cfg.OrgClient.Share = sec.Share
		cfg.OrgClient.Scope = sec.Scope
		cfg.OrgClient.PushIntervalSeconds = sec.PushIntervalSeconds
		cfg.OrgClient.MaxPushBytes = sec.MaxPushBytes
		// Enabled / OrgServerURL / KeychainID intentionally untouched.
	case "otel":
		// OTel exporter (P4.12 / review row A6). Whole-struct replace:
		// every field is an operator knob with no sibling owner.
		var sec config.OTelExporterConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode otel: %w", err)
		}
		cfg.Exporter.OTel = sec
	case "profiles":
		// Track R (P2.7): compression-profile assignments. Names are
		// validated against the resolvable profile set (built-ins +
		// user profiles, P3.4) so a typo (or a stale UI) can't write
		// an assignment the proxy would have to fall back from at
		// runtime.
		var sec config.ProfilesConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode profiles: %w", err)
		}
		store := config.ProfileStore{Dir: config.DefaultProfilesDir(configPath)}
		if err := store.Validate(sec.Default); err != nil {
			return err
		}
		for provider, name := range sec.ByProvider {
			if err := store.Validate(name); err != nil {
				return fmt.Errorf("assignment %q: %w", provider, err)
			}
		}
		for tool, name := range sec.ByTool {
			if err := store.Validate(name); err != nil {
				return fmt.Errorf("tool assignment %q: %w", tool, err)
			}
		}
		cfg.Profiles = sec
	case "guard":
		// Guard layer (security-routing usability arc G1.1). Closed
		// enums are validated HERE so a stale or buggy form can't
		// write a value the daemon would only reject at next start.
		var sec config.GuardConfig
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode guard: %w", err)
		}
		for _, e := range []struct {
			field, val string
			allowed    []string
		}{
			{"mode", sec.Mode, []string{"off", "observe", "enforce"}},
			{"proxy.egress_action", sec.Proxy.EgressAction, []string{"flag", "mask", "deny"}},
			{"alerts.min_severity", sec.Alerts.MinSeverity, []string{"info", "warn", "high", "critical"}},
			// prompt.mode (§8.1, PHASE-3b-DASHBOARD) is now a real
			// dashboard field (web/src/pages/settings/sectionSpecs.ts
			// "Guard.Prompt" group) — the frontend's draft is a full
			// clone of the loaded config so a real save always sends a
			// complete Prompt object, never an omitted key. This entry
			// gives a friendly per-field error before the heavier
			// config.Validate pass below (which also runs
			// validateGuardPrompt over Mode/Detectors/Allow/
			// ReconsiderTTL/MaxFindings — this only front-runs the mode
			// enum with a clearer field name). sec.Prompt is no longer
			// discarded — [guard.prompt] round-trips through this
			// section like every other guard sub-section.
			{"prompt.mode", sec.Prompt.Mode, []string{"off", "warn", "ask-once", "block", "redact"}},
		} {
			if !slices.Contains(e.allowed, e.val) {
				return fmt.Errorf("guard %s: %q not one of %v", e.field, e.val, e.allowed)
			}
		}
		prior := cfg.Guard
		// Cloud is the D1 network-egress opt-in — a hand-written
		// config decision the dashboard must never be able to flip
		// (the same selective copy the org case uses for enrolment
		// identity).
		sec.Cloud = prior.Cloud
		// OrgBundle is org-client-owned; CEL is the parse-but-reject
		// v2 gate. Neither is on the form — preserve.
		sec.Rules.OrgBundle = prior.Rules.OrgBundle
		sec.Rules.CEL = prior.Rules.CEL
		// Boundary lists distinguish nil (engine defaults) from
		// explicitly empty ("none"); a form can't express that, so
		// empty preserves prior and "none" stays a config-file edit.
		if len(sec.Boundary.AllowPaths) == 0 {
			sec.Boundary.AllowPaths = prior.Boundary.AllowPaths
		}
		if len(sec.Boundary.ProtectedBranches) == 0 {
			sec.Boundary.ProtectedBranches = prior.Boundary.ProtectedBranches
		}
		cfg.Guard = sec
	case "routing":
		// Model-routing layer (security-routing usability arc R1.1).
		// The form owns the adoption-funnel knobs ONLY: gate, mode,
		// policy template, retention, stickiness, calibration, rate-
		// limit window. Everything else under [routing] — tiers,
		// benchmark_files, path_classes, privacy rules, budget scopes,
		// reliability, key_pool (holds API keys), local_upstreams —
		// is a complex shape or carries secrets: those stay
		// config-file-only, so decode the editable subset and keep the
		// rest of the prior section wholesale. §R23 posture: this PUT
		// writes THIS node's config file only — routing deliberately
		// has no remote mode surface.
		//
		// [[routing.rules]] (R2.2, Q3 FULL) keeps this case as its ONE
		// writer with an explicit escape hatch: RulesTOML absent (the
		// section form never sends it) = rules preserved wholesale
		// exactly as R1.1 shipped; RulesTOML present = the fragment
		// replaces them — gated by the same parse + config.Load shape
		// checks + error-severity compiler lint the /api/routing/
		// policy/lint endpoint runs, so a refusal leaves the file
		// untouched. An explicit empty string clears all custom rules.
		var sec struct {
			Enabled                  bool                                `json:"Enabled"`
			Mode                     string                              `json:"Mode"`
			Policy                   string                              `json:"Policy"`
			DecisionLogRetentionDays int                                 `json:"DecisionLogRetentionDays"`
			Stickiness               config.RoutingStickinessConfig      `json:"Stickiness"`
			RateLimitWindow          config.RoutingRateLimitWindowConfig `json:"RateLimitWindow"`
			Calibration              config.RoutingCalibrationConfig     `json:"Calibration"`
			RulesTOML                *string                             `json:"RulesTOML"`
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			return fmt.Errorf("decode routing: %w", err)
		}
		// Validate HERE what config.Load would reject at the next
		// daemon start — the file must never go bad through this seam.
		if !slices.Contains([]string{"off", "advise", "enforce"}, sec.Mode) {
			return fmt.Errorf("routing mode: %q not one of [off advise enforce]", sec.Mode)
		}
		policies := []string{"custom"}
		for _, t := range routing.Templates() {
			policies = append(policies, t.Name)
		}
		if !slices.Contains(policies, sec.Policy) {
			return fmt.Errorf("routing policy: %q not one of %v", sec.Policy, policies)
		}
		if sec.RateLimitWindow.HeadroomPct < 0 || sec.RateLimitWindow.HeadroomPct > 100 {
			return fmt.Errorf("routing rate_limit_window.headroom_pct: %d must be in [0, 100]", sec.RateLimitWindow.HeadroomPct)
		}
		if sec.Calibration.MinSamples < 0 {
			return fmt.Errorf("routing calibration.min_samples: %d must be >= 0", sec.Calibration.MinSamples)
		}
		next := cfg.Routing
		next.Enabled = sec.Enabled
		next.Mode = sec.Mode
		next.Policy = sec.Policy
		next.DecisionLogRetentionDays = sec.DecisionLogRetentionDays
		next.Stickiness = sec.Stickiness
		next.RateLimitWindow = sec.RateLimitWindow
		next.Calibration = sec.Calibration
		if sec.RulesTOML != nil {
			rules, problems := parseRoutingRulesTOML(*sec.RulesTOML)
			if len(problems) == 0 {
				_, gateProblems := gateRoutingRules(next, rules)
				problems = gateProblems
			}
			if len(problems) > 0 {
				return fmt.Errorf("routing rules refused (file untouched): %s", strings.Join(problems, "; "))
			}
			next.Rules = rules
		}
		cfg.Routing = next
	case "pricing":
		return errors.New("pricing has its own endpoint /api/config/pricing")
	default:
		return fmt.Errorf("unknown section %q", name)
	}
	return nil
}

// handleConfigBackup serves the config.toml.bak safety net created on
// every dashboard save (usability arc P1.15):
//
//   - GET:  {exists, backup_path, modified_at, content} — the prior
//     config verbatim so the user can eyeball what restore brings back.
//   - POST: swaps config.toml and config.toml.bak (the bak is
//     validated as parseable TOML first). Because it's a SWAP, restore
//     is its own undo. Response carries restart_required like every
//     non-pricing config write.
func (s *Server) handleConfigBackup(w http.ResponseWriter, r *http.Request) {
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured", http.StatusConflict)
		return
	}
	bakPath := s.opts.ConfigPath + ".bak"
	switch r.Method {
	case http.MethodGet:
		// Serialize the .bak READ with the writers (Fix 3): config.WriteToml
		// overwrites .bak NON-atomically (internal/config/write.go copies
		// config.toml → .bak in place), so an unguarded read here could observe a
		// half-written backup mid-save. configWriteMu is the same lock every
		// config writer holds across its .bak overwrite, so taking it here makes
		// the read see only whole-file states (never a torn .bak).
		s.configWriteMu.Lock()
		defer s.configWriteMu.Unlock()
		body, err := os.ReadFile(bakPath)
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, map[string]any{"exists": false, "backup_path": bakPath})
			return
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		var modifiedAt string
		if fi, statErr := os.Stat(bakPath); statErr == nil {
			modifiedAt = fi.ModTime().UTC().Format(time.RFC3339)
		}
		// The preview is the SAME read path as GET /api/config, just a
		// different serialization: an unredacted .bak publishes the very T2
		// credentials §4.3 redacts from the struct. Parse it, substitute the
		// credential values, and fail closed (withhold content, say so) if
		// any value cannot be substituted safely. Restore (POST) reads the
		// file from disk and is unaffected.
		resp := map[string]any{
			"exists":      true,
			"backup_path": bakPath,
			"modified_at": modifiedAt,
		}
		var bakCfg config.Config
		if err := toml.Unmarshal(body, &bakCfg); err != nil {
			// Unparseable backup: it cannot be scanned for credentials, and
			// POST would refuse to restore it anyway. Report it honestly
			// instead of echoing bytes that were never inspected.
			resp["content_withheld"] = "the backup is not valid TOML, so it could not be checked for credentials before display"
			writeJSON(w, resp)
			return
		}
		content, ok := redactSecretsInTOMLText(string(body), &bakCfg)
		if !ok {
			resp["content_withheld"] = "the backup contains a credential that could not be safely masked for display — open " + bakPath + " directly"
			writeJSON(w, resp)
			return
		}
		resp["content"] = content
		writeJSON(w, resp)
	case http.MethodPost:
		// The restore swaps config.toml ↔ .bak — a read-modify-write of the
		// shared file, so it serializes with the section/pricing save paths
		// (Fix 1). See Server.configWriteMu.
		s.configWriteMu.Lock()
		defer s.configWriteMu.Unlock()
		bak, err := os.ReadFile(bakPath)
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "no backup exists yet — backups are created on the first dashboard save", http.StatusNotFound)
			return
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		// Refuse to restore a corrupt backup: it must parse as TOML
		// into the Config struct.
		var probe config.Config
		if err := toml.Unmarshal(bak, &probe); err != nil {
			http.Error(w, "backup does not parse as valid config TOML; not restoring: "+err.Error(),
				http.StatusUnprocessableEntity)
			return
		}
		cur, err := os.ReadFile(s.opts.ConfigPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			writeErr(w, err)
			return
		}
		// Swap: bak → config.toml (atomic temp+rename), then the prior
		// current → .bak so a second restore undoes the first.
		tmp := s.opts.ConfigPath + ".tmp"
		if err := os.WriteFile(tmp, bak, 0o644); err != nil { //nolint:gosec // G306: non-secret config.toml restore; mirrors the original's readable perms (the write.go precedent).
			writeErr(w, err)
			return
		}
		if err := os.Rename(tmp, s.opts.ConfigPath); err != nil {
			writeErr(w, err)
			return
		}
		if len(cur) > 0 {
			if err := os.WriteFile(bakPath, cur, 0o644); err != nil { //nolint:gosec // G306: backup of the non-secret config.toml; mirrors the original's readable perms (the write.go precedent).
				// Non-fatal: the restore landed; only the undo-of-undo
				// is degraded. Report it honestly.
				s.notifyConfigSaved()
				writeJSON(w, map[string]any{
					"restored":         true,
					"swap_incomplete":  true,
					"restart_required": true,
				})
				return
			}
		}
		s.notifyConfigSaved()
		writeJSON(w, map[string]any{
			"restored":         true,
			"restart_required": true,
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleAntigravityBridge serves GET /api/admin/antigravity-bridge.exe
// — streams the Windows-side helper observer ships in `bin/`.
//
// Convenience download for users on WSL2 who installed observer via
// npm (no `make build` to produce the binary). The bridge is a tiny
// (~9 MB) Windows amd64 executable; observer detects WSL2 + opt-in
// and shells out to it via powershell.exe to bridge the WSL→Windows-
// localhost network gap when calling Antigravity's local
// language_server gRPC API.
//
// Lookup mirrors locateBridgeBinary's order in the antigravity
// adapter — same OBSERVER_ANTIGRAVITY_BRIDGE override; same neighbor
// + cwd/bin fallback. Returns 404 if the binary isn't present
// (caller surfaces a friendly "run `make build` to produce it" hint).
func (s *Server) handleAntigravityBridge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET or HEAD only", http.StatusMethodNotAllowed)
		return
	}
	bridge := findAntigravityBridge()
	if bridge == "" {
		http.Error(w, "antigravity-bridge.exe not found in bin/. Build observer with `make build` to produce it, or set $OBSERVER_ANTIGRAVITY_BRIDGE to its path.",
			http.StatusNotFound)
		return
	}
	// HEAD path serves headers only so the dashboard can probe
	// availability + size without downloading the ~9MB binary.
	if r.Method == http.MethodHead {
		st, err := os.Stat(bridge)
		if err != nil {
			writeErr(w, fmt.Errorf("stat bridge: %w", err))
			return
		}
		w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
		w.Header().Set("Content-Disposition", `attachment; filename="antigravity-bridge.exe"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
		w.WriteHeader(http.StatusOK)
		return
	}
	body, err := os.ReadFile(bridge)
	if err != nil {
		writeErr(w, fmt.Errorf("read bridge: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", `attachment; filename="antigravity-bridge.exe"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	_, _ = w.Write(body)
}

// findAntigravityBridge mirrors the adapter-side resolution but
// is duplicated here to avoid a dashboard→adapter import cycle.
// Returns the first existing path, or "" when none.
func findAntigravityBridge() string {
	if env := strings.TrimSpace(os.Getenv("OBSERVER_ANTIGRAVITY_BRIDGE")); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "antigravity-bridge.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "bin", "antigravity-bridge.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// handleAdminRestart serves POST /api/admin/restart — schedules an
// os.Exit(0) ~500ms after returning so the browser response lands
// before the process tears down. Whether the daemon comes back depends
// on the supervisor (npm wrapper, systemd, manual relaunch). The UI
// shows a "if you don't see the dashboard in 10s, relaunch manually"
// hint after firing this.
//
// Q3 DECISION (usability arc P4.14, 2026-06-11): the daemon does NOT
// self-respawn, and the web UI deliberately ships NO generic
// restart/stop button — the restart-pending banner naming `observer
// start` is the product. Reasons, in force-order:
//  1. The P4.7 live verify showed a routed tool with the daemon down
//     HANGS (no bypass, no fast fail). A stop button whose comeback
//     is best-effort turns one failed respawn into frozen AI tools
//     plus a dead dashboard to debug it from.
//  2. The daemon doesn't own its log destination — real launches
//     redirect stdout/stderr at the shell (the operator's live WSL
//     daemon included). A respawned child silently loses the logs.
//     Daemon-owned log files are the prerequisite, not a detail.
//  3. A child must out-race the parent's port teardown on :8820 and
//     the dashboard port — retry machinery whose failure mode is
//     exactly case 1.
//  4. Supervised contexts (VS Code extension, systemd Restart=) make
//     exit-and-revive work today; this endpoint stays for THEM.
//
// Revisit only alongside daemon-owned logging.
//
// No CSRF token: the dashboard binds to localhost-only by default and
// the project hasn't shipped a network-mode threat model. Add a
// per-session token if remote-mode lands later.
func (s *Server) handleAdminRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// The live-traffic report for the confirm dialog (config_keys.go).
		s.handleAdminRestartStatus(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	// Restart is driven by the cmd-owned lifecycle hook (graceful shutdown +
	// self re-exec). Nil means this process mode can't self-restart (e.g. a
	// native-Windows daemon, or a standalone read-only surface) — report it
	// honestly rather than os.Exit into a process nothing will revive.
	if s.opts.RestartFunc == nil {
		http.Error(w, `{"error":"restart from the dashboard isn't available in this process mode — relaunch the daemon manually"}`, http.StatusNotImplemented)
		return
	}
	// The hook preflights the config; a refusal (config wouldn't come back)
	// means the daemon keeps running and the operator sees why.
	if err := s.opts.RestartFunc(); err != nil {
		s.opts.Logger.Warn("admin restart refused", "error", err)
		writeErr(w, err)
		return
	}
	s.opts.Logger.Info("admin restart scheduled — graceful shutdown + re-exec")
	writeJSON(w, map[string]any{"restart_scheduled": true, "delay_ms": 300})
}

// handleBackfillStatus serves GET /api/backfill/status — surfaces every
// `observer backfill --<mode>` flag with a candidate-row count where
// the candidate set is computable in pure SQL (is-sidechain, cache-tier,
// message-id). The file-walking modes (per-adapter scans against
// ~/.claude/projects, opencode.db, etc.) report `candidates: -1` and a
// note that a scan is needed — running the backfill itself is the
// only way to count there.
//
// Every mode listed here must have a matching entry in
// allowlistedBackfillModes (backfill_run.go) so the panel's Run button
// can actually start it via POST /api/backfill/run.
func (s *Server) handleBackfillStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	type modeStatus struct {
		Mode           string `json:"mode"`
		Flag           string `json:"flag"`
		Description    string `json:"description"`
		Candidates     int64  `json:"candidates"` // -1 = needs file scan
		CandidatesNote string `json:"candidates_note,omitempty"`
	}

	// SQL-checkable modes — count rows that haven't been touched by the
	// matching backfill. Approximate (a NULL column may be platform-truth
	// rather than missing data); the figures are advisory, not gates.
	sqlModes := []struct {
		mode, flag, description, query string
	}{
		{
			"is-sidechain", "--is-sidechain",
			"actions.is_sidechain from JSONL (Claude Code parent/sub-agent boundary)",
			`SELECT COUNT(*) FROM actions WHERE is_sidechain IS NULL`,
		},
		{
			"cache-tier", "--cache-tier",
			"api_turns.cache_creation_1h_tokens from JSONL (since migration 008)",
			`SELECT COUNT(*) FROM api_turns WHERE cache_creation_tokens > 0
			   AND (cache_creation_1h_tokens IS NULL OR cache_creation_1h_tokens = 0)`,
		},
		{
			"message-id", "--message-id",
			"actions + token_usage.message_id (claudecode + codex + cursor + opencode)",
			`SELECT
			   (SELECT COUNT(*) FROM actions      WHERE message_id IS NULL OR message_id = '')
			 + (SELECT COUNT(*) FROM token_usage WHERE message_id IS NULL OR message_id = '')`,
		},
	}
	out := make([]modeStatus, 0, len(sqlModes)+11)
	for _, m := range sqlModes {
		var n int64
		// s.opts.DB, not s.db(): backfill operates on the real DB, so
		// its candidate counts must describe it even in demo mode.
		if err := s.opts.DB.QueryRowContext(r.Context(), m.query).Scan(&n); err != nil {
			s.opts.Logger.Warn("backfill status query", "mode", m.mode, "err", err)
			n = -1
		}
		out = append(out, modeStatus{
			Mode: m.mode, Flag: m.flag, Description: m.description, Candidates: n,
		})
	}

	// File-walking modes — count requires running a per-adapter scan
	// over source files (claudecode JSONL, opencode.db, etc.). Surface
	// the mode name and let the user kick the run from the CLI.
	fileWalk := []struct{ mode, flag, description string }{
		{"opencode-message-id", "--opencode-message-id", "opencode.db row IDs (assistant rows + parent message ids)"},
		{"opencode-parts", "--opencode-parts", "opencode tool output excerpts from State.Output / Metadata.Output"},
		{"opencode-tokens", "--opencode-tokens", "re-ingest opencode token_usage rows missed pre-fix"},
		{"openclaw-action-types", "--openclaw-action-types", "spawn_subagent action_type for sessions_spawn rows"},
		{"openclaw-model", "--openclaw-model", "sessions.model + workspace_dir from sessions.json aliases"},
		{"openclaw-reasoning", "--openclaw-reasoning", "preceding_reasoning from openclaw JSONL assistant text/thinking parts"},
		{"codex-reasoning", "--codex-reasoning", "codex preceding_reasoning from agent_message events"},
		{"cursor-model", "--cursor-model", "actions.model from cursor rawHookPayload.Model"},
		{"copilot-message-id", "--copilot-message-id", "actions.message_id from spanId / parentSpanId"},
		{"pi-message-id", "--pi-message-id", "actions.message_id from pi message ids"},
		{"claudecode-user-prompts", "--claudecode-user-prompts", "user_prompt action rows for Claude Code text user lines"},
		{"claudecode-api-errors", "--claudecode-api-errors", "api_error action rows for Claude Code system/api_error JSONL records (content-policy blocks, rate limits, invalid-request errors)"},
		{"cowork-rescan", "--cowork-rescan", "Fast cowork-only rescan — walks Cowork audit.jsonl tree only. Use after adding 'cowork' to enabled_adapters mid-flight, or when --all would be too slow"},
		{"cowork-project-root", "--cowork-project-root", "Re-attribute Cowork sessions whose project_id was wrongly set to observer's own repo (pre-v1.4.54 Windows-path bug). Walks each local_<id>/audit.jsonl + sidecar, recomputes project root via crossmount translation, updates sessions + actions on mismatch"},
		{"codex-rescan", "--codex-rescan", "Fast codex-only rescan — re-walks every codex rollout JSONL from offset 0 to pick up v1.4.53 adapter additions: token_usage.web_search_requests + ActionRateLimit rows from token_count.rate_limits + codex.reasoning rows from response_item.reasoning. Idempotent via (source_file, source_event_id) UNIQUE"},
		{"antigravity", "--antigravity-rescan", "Re-walk Antigravity .pb / state.vscdb files and re-ingest via the adapter: local decrypt first, fall back to language_server gRPC when [observer.antigravity] network_recovery = \"local\" is set"},
		{"antigravity-project-root", "--antigravity-project-root", "Re-attribute antigravity sessions / actions to the correct project + refresh session.model and session.started_at from the state.vscdb index entry. Also lifts per-turn token_usage rows + the actual model name (e.g. claude-sonnet-4-5) into the DB via the language_server's GetCascadeTrajectory endpoint (best-effort, requires the conversation be loaded by a running language_server)"},
		{"gemini-cli", "--gemini-cli-rescan", "Re-walk Gemini CLI session JSON / JSONL under ~/.gemini/tmp/<hash>/chats/. gemini-cli has no surgical column backfills; this is its only retroactive path"},
		{"copilot-cli", "--copilot-cli-rescan", "Re-walk GitHub Copilot CLI session data: events.jsonl under ~/.copilot/session-state AND process-*.log under ~/.copilot/logs (cross-mount aware). Run after enabling `copilot --log-level debug` to retrofit Tier-1 accurate input/cache/reasoning tokens onto historical sessions"},
		{"hermes-rescan", "--hermes-rescan", "Fast rescan of the Hermes Agent tree only — re-walks every state.db under ~/.hermes (cross-mount aware) from messages.id=0. Useful for importing sessions that predate the `observer init --hermes` plugin install. Idempotent"},
		{"clinecli-rescan", "--clinecli-rescan", "Fast rescan of the Cline CLI tree only — re-walks sessions.db + each session's messages.json, re-emitting session/prompt/tool/metrics rows. Useful for importing sessions that pre-date adapter install. Idempotent"},
		{"cache-rescan", "--cache-rescan", "Re-walk claude-code transcripts through the Tier-2 cache observation engine to populate historical cache_segments / cache_entries / cache_events. Use after enabling [cachetrack] on a daemon with historical traffic, or after upgrading past a cachetrack fix. Proxy-observed turns are skipped (no double-write); idempotent"},
		{"zed-rescan", "--zed-rescan", "Fast rescan of the Zed native-agent tree only — re-walks every threads.db under the configured Zed watch roots from watermark 0, forcing every thread to re-emit regardless of its stored updated_at cursor. threads.db is a watermark store, so a thread that predates the daemon first observing its file is never re-read until its NEXT turn — this is the only retroactive path for pre-existing Zed conversations. Idempotent via (source_file, source_event_id) UNIQUE"},
		{"openclaw-project-root", "--openclaw-project-root", "Re-attribute openclaw action / session rows to the correct project when sessions.json workspaceDir previously collapsed to the [openclaw] placeholder or a foreign-OS path"},
		{"openclaw-session-id", "--openclaw-session-id", "Collapse historical openclaw split sessions where sessions.json used the raw sessionId but JSONL / task_runs used the alias session key"},
		{"codex-project-root", "--codex-project-root", "Re-attribute codex action / token / session rows to the correct project when their cwd was a Windows-style path that previously misresolved to observer's own repo"},
		{"claudecode-project-root", "--claudecode-project-root", "Re-attribute claude-code action / token / session rows to the correct project when their cwd was a Windows-style path that previously misresolved to observer's own repo"},
		{"cursor-user-prompts", "--cursor-user-prompts", "Insert user_prompt action rows for Cursor sessions by walking agent-transcripts JSONL — fills the gap for sessions before the beforeSubmitPrompt hook was installed"},
		{"cursor-subagents", "--cursor-subagents", "Walk Cursor agent-transcripts/<session>/subagents/*.jsonl and ingest as sidechain rows under the parent session (IsSidechain=true)"},
	}
	for _, m := range fileWalk {
		out = append(out, modeStatus{
			Mode: m.mode, Flag: m.flag, Description: m.description,
			Candidates:     -1,
			CandidatesNote: "file scan needed — candidates are discovered as the run walks source files",
		})
	}

	// --tasks (docs/task-tracking.md "Backfill") is a pure re-read of
	// actions rows already in the DB — no file walk, unlike everything
	// above in fileWalk — but it re-DERIVES rather than fills a
	// "still missing" column, so there is no shrinking-to-zero
	// candidate count the way is-sidechain/cache-tier/message-id have
	// one: re-running it is a no-op, not a sign nothing is left to do.
	{
		var n int64
		if err := s.opts.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM actions WHERE action_type = 'todo_update'`).Scan(&n); err != nil {
			s.opts.Logger.Warn("backfill status query", "mode", "tasks", "err", err)
			n = -1
		}
		out = append(out, modeStatus{
			Mode: "tasks", Flag: "--tasks",
			Description:    "Re-derive task_items / task_transitions (session-level task/todo/plan tracking, docs/task-tracking.md) from todo_update / post_tool_batch action rows already in the DB. No adapter re-parse, no source-file walk. Idempotent — safe to re-run after enabling [tasks].enabled on a daemon with historical traffic.",
			Candidates:     n,
			CandidatesNote: "todo_update actions rows only — post_tool_batch candidates aren't cheaply countable without the same raw_tool_input scan the backfill itself does",
		})
	}

	// Registry-derived per-adapter scan lane — one row per registered
	// adapter, backed by `observer scan --force --adapter <tool>` (the
	// generic re-walk; idempotent via the (source_file, source_event_id)
	// UNIQUE index, and it overrides enabled_adapters for the run).
	// Derived from internal/integration so a new adapter's row appears
	// here automatically instead of trailing a hand-maintained list.
	// Kept in lockstep with allowlistedBackfillModes by the same init()
	// derivation in backfill_run.go (pinned in settings_test.go).
	caps := integration.Capabilities()
	slices.SortFunc(caps, func(a, b integration.Capability) int {
		return strings.Compare(a.Tool, b.Tool)
	})
	for _, c := range caps {
		out = append(out, modeStatus{
			Mode:           "scan-" + c.Tool,
			Flag:           "scan --force --adapter " + c.Tool,
			Description:    "Generic re-walk of every " + c.Tool + " session file via the adapter — imports sessions that pre-date the adapter (or an enabled_adapters fix). Idempotent; scoped to this adapter only",
			Candidates:     -1,
			CandidatesNote: "file scan needed — candidates are discovered as the run walks source files",
		})
	}

	writeJSON(w, map[string]any{
		"modes": out,
	})
}

// loadConfigForDashboard wraps config.Load with a friendlier behaviour
// for the dashboard's read path: when the file doesn't exist yet,
// return defaults rather than erroring. The Settings UI shows defaults
// + a "config file not yet created" hint until the user saves something.
func loadConfigForDashboard(path string) (config.Config, error) {
	if path == "" {
		return config.Default(), nil
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return config.Default(), nil
	}
	return config.Load(config.LoadOptions{GlobalPath: path})
}

// writeConfigToml delegates to config.WriteToml — THE shared config
// write owner (.bak + atomic temp-rename), also used by the `observer
// profile assign` CLI. Kept as a local name so the handler call sites
// read naturally.
func writeConfigToml(path string, cfg config.Config) error {
	return config.WriteToml(path, cfg)
}
