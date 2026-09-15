package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/compression/conversation"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/messagesummary"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/profilerouter"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/stash"
	"github.com/marmutapp/superbased-observer/internal/stashalign"
)

// This file assembles the Track-R compression profile router
// (usability arc §2.3): per-profile conversation pipelines resolved at
// the proxy boundary, session-sticky, with shared single-instance
// infrastructure. The proxy hot path is untouched — routing rides the
// existing CompressInSession seam, which already carries provider and
// session ID.

// profilePipelineDeps carries the single-instance infrastructure every
// profile pipeline shares. One owner per piece of state: profiles tune
// PARAMETERS (modes, ratios, thresholds, sub-toggles); the stores and
// caches below exist once per daemon and are master-config-owned.
type profilePipelineDeps struct {
	scrubber *scrub.Scrubber
	// symbolLookup is nil when the code index is unavailable — pipelines
	// degrade to filename-only marker enrichment.
	symbolLookup conversation.SymbolLookup
	// stash is nil unless the MASTER config enables the stash store.
	// A profile whose overlay enables stash without the master store
	// gets no stash (install infra is not profile parameter space);
	// all built-in recipes pin stash off anyway (V7-24).
	stash *stash.Stash
	// aggressiveCode* carry the resolved [codeintel.compression] body-
	// collapse settings (master-owned, like stash, and OFF by default).
	// Applied to each profile pipeline only when a stash is also wired
	// (collapse needs the stash to hold collapsed originals). exts is the
	// opt-in extension set; empty means none even when enabled.
	aggressiveCodeEnabled bool
	aggressiveCodeExts    map[string]bool
	aggressiveCodePreview bool
	// authCache + recorder are nil unless the MASTER config enables
	// rolling summaries — the proxy feeds one auth cache, so rolling
	// is master-gated infrastructure with profile-tunable models and
	// thresholds. (P3.4 custom profiles wanting rolling without the
	// master toggle will need this revisited.)
	authCache *messagesummary.AuthCache
	recorder  *messagesummary.DBRecorder
}

// newCompressionRouter builds the profile router the proxy uses as its
// compressor: built-in profiles resolve lazily per provider assignment
// ([profiles] in config.toml, baked defaults anthropic→claude-code /
// openai→codex-safe), each profile gets one immutable pipeline, and
// sessions stick to the pipeline they first resolved. Returns the
// router, the shared rolling-summary auth cache (nil when rolling is
// disabled) for the proxy's credential capture, and the P2.5
// hot-reload hook: loadFresh re-reads config exactly the way the boot
// config was produced (including the deprecated --recipe alias) and
// the router re-points so NEW sessions resolve against the updated
// [profiles] table and compression parameters — existing sessions
// keep their instances.
func newCompressionRouter(cfg config.Config, masterPath string, loadFresh func() (config.Config, error), database *sql.DB, logger *slog.Logger) (routerCompressor, *messagesummary.AuthCache, func()) {
	deps := profilePipelineDeps{}
	// Scrubbing policy is install-level ([observer.secrets]), never a
	// tuning parameter — one scrubber for every profile.
	if cfg.Observer.Secrets.EnableScrubbing {
		deps.scrubber = scrub.NewWithExtra(cfg.Observer.Secrets.ExtraPatterns)
	} else {
		deps.scrubber = scrub.New()
	}
	// V7-11 / v1.7.7: pre-fetch code-index symbols for the marker
	// enrichment in LogsCompressor. The native codeintel engine answers
	// from the node-local index; when its index is still empty the
	// adapter's per-call Available() gate reports false and the marker
	// enrichment degrades to filename-only. Never abort startup on a
	// lookup failure; this is best-effort augmentation. The provider is
	// master-owned: one shared engine for all profiles, and it self-heals
	// as `observer start` indexes projects (buildCodeIntelProvider).
	deps.symbolLookup = codeintelPipelineAdapter{p: buildCodeIntelProvider(cfg, database, logger)}
	// Aggressive code-collapse settings (codeintel Phase 2) — master-
	// owned, OFF by default. Resolved once here; applied per profile in
	// newProfilePipeline when a stash is wired. The per-language opt-in
	// is expanded to the concrete extension set the collapse hook checks.
	if cfg.CodeIntel.Enabled && cfg.CodeIntel.Compression.CodeAggressive {
		deps.aggressiveCodeEnabled = true
		deps.aggressiveCodeExts = aggressiveExtsFor(cfg.CodeIntel.Compression.AggressiveLanguages)
		deps.aggressiveCodePreview = cfg.CodeIntel.Compression.PreviewOnly
	}
	if cfg.Compression.Conversation.Stash.Enabled {
		st, err := stash.New(stash.Options{
			Dir:        cfg.Compression.Conversation.Stash.Dir,
			MaxTotalMB: cfg.Compression.Conversation.Stash.MaxTotalMB,
		})
		if err != nil {
			logger.Warn("proxy: stash init failed; CCR disabled", "err", err)
		} else {
			deps.stash = st
			// V7-8: advertise the active stash dir to any
			// later-starting `observer serve` MCP server on this
			// host. The MCP side reads the sidecar at startup and
			// warns on mismatch. Failure to write is non-fatal —
			// we still ran the stash successfully on this side.
			if home, herr := stashalign.DefaultObserverHome(); herr == nil {
				if werr := stashalign.WriteSidecar(home, cfg.Compression.Conversation.Stash.Dir); werr != nil {
					logger.Warn("proxy: stash-dir sidecar write failed; cross-process detection will not fire",
						"err", werr, "sidecar", stashalign.SidecarPath(home))
				}
			}
		}
	}
	if cfg.Compression.Conversation.Rolling.Enabled {
		deps.authCache = messagesummary.NewAuthCache(cfg.Compression.Conversation.Rolling.AuthCacheSize)
		deps.recorder = messagesummary.NewDBRecorder(database, costEnginePricingAdapter{e: acquireProcessCostEngine(context.Background(), cfg, database, logger)})
	}

	// The Resolve/Build closures read assignments and master
	// parameters through an atomically swappable snapshot so the P2.5
	// hot-reload can re-point them without rebuilding the router.
	snap := &atomic.Pointer[profileConfigSnapshot]{}
	snap.Store(&profileConfigSnapshot{master: cfg.Compression, profiles: cfg.Profiles, experiments: cfg.Experiments})

	// R3: lazy, mtime-cached view of repo-local override files
	// (<root>/.observer/config.toml, allow-listed keys only).
	overlays := config.NewProjectOverlays()
	overlays.Warnf = func(format string, args ...any) {
		logger.Warn(fmt.Sprintf(format, args...))
	}
	// P3.4: user profiles (~/.observer/profiles/*.toml) resolve
	// alongside the built-ins; their content stamp rides the instance
	// key so edits apply to new sessions without a restart.
	store := config.ProfileStore{Dir: config.DefaultProfilesDir(masterPath)}

	// The default profile's pipeline is built eagerly from master
	// parameters — it is the never-fail fallback for unresolvable or
	// broken profile assignments (traffic proceeds on master params,
	// never blocks).
	fallback := newProfilePipeline(cfg.Compression, deps)
	router := profilerouter.New(profilerouter.Options[pipelineAdapter]{
		Resolve: func(provider, tool, cwd, sessionID string) string {
			s := snap.Load()
			profiles := s.profiles
			root, raw, stamp := lookupProjectOverlay(overlays, cwd, masterPath)
			if raw != nil {
				// Project [profiles] keys override the global
				// assignment table for this repo's traffic.
				profiles = config.ProjectProfiles(profiles, raw)
			}
			// Experiment tier (P6.4): an ACTIVE experiment matching
			// this traffic class claims the session and hash-assigns
			// its arm — winning over assignments and project overlays
			// alike (an explicit, time-bounded operator action;
			// stopping restores them). Per-request traffic
			// (sessionID "") never enters experiments.
			name, _, _ := config.ResolveProfileNameForSession(profiles, s.experiments, provider, tool, sessionID)
			return profileInstanceKey(name, store.Stamp(name), root, stamp)
		},
		Build: func(key string) (pipelineAdapter, error) {
			name, root := splitProfileKey(key)
			resolved, _, err := store.ResolveCompression(snap.Load().master, name)
			if err != nil {
				return pipelineAdapter{}, err
			}
			if root != "" {
				if raw, _, ok := overlays.Lookup(root); ok {
					resolved, err = config.ProjectCompression(resolved, raw)
					if err != nil {
						return pipelineAdapter{}, err
					}
				}
			}
			return newProfilePipeline(resolved, deps), nil
		},
		DefaultProfile: config.DefaultProfileName,
		Fallback:       fallback,
		Warnf: func(format string, args ...any) {
			logger.Warn(fmt.Sprintf(format, args...))
		},
		OnResolve: func(provider, tool, cwd, sessionID, key string) {
			name, root := splitProfileKey(key)
			logger.Debug("proxy: compression profile resolved",
				"provider", provider, "tool", tool, "cwd", cwd,
				"session_id", sessionID, "profile", name, "project_root", root)
		},
	})

	// reload is the P2.5 hook the dashboard's config-save path fires:
	// re-read config.toml, swap the snapshot, bump the router version
	// (new sessions re-resolve; existing sessions keep their sticky
	// instances). The conversation master SWITCH stays restart-gated —
	// this router only exists when it was on at boot, and a flip in
	// the file keeps the restart-pending banner honest — so the boot
	// enablement is pinned over the re-read value.
	reload := func() {
		fresh, err := loadFresh()
		if err != nil {
			logger.Warn("profiles hot-reload: config reload failed; keeping current assignments", "err", err)
			return
		}
		master := fresh.Compression
		master.Conversation.Enabled = cfg.Compression.Conversation.Enabled
		snap.Store(&profileConfigSnapshot{master: master, profiles: fresh.Profiles, experiments: fresh.Experiments})
		router.Update(func(provider, tool, cwd, sessionID string) string {
			profiles := fresh.Profiles
			root, raw, stamp := lookupProjectOverlay(overlays, cwd, masterPath)
			if raw != nil {
				profiles = config.ProjectProfiles(profiles, raw)
			}
			name, _, _ := config.ResolveProfileNameForSession(profiles, fresh.Experiments, provider, tool, sessionID)
			return profileInstanceKey(name, store.Stamp(name), root, stamp)
		}, newProfilePipeline(master, deps))
		logger.Info("profiles hot-reload applied: new sessions resolve against the updated config",
			"default", config.ResolveProfileName(fresh.Profiles, "", ""),
			"anthropic", config.ResolveProfileName(fresh.Profiles, models.ProviderAnthropic, ""),
			"openai", config.ResolveProfileName(fresh.Profiles, models.ProviderOpenAI, ""))
	}
	return routerCompressor{r: router}, deps.authCache, reload
}

// profileConfigSnapshot is the unit the hot-reload swaps: the master
// compression parameters, the [profiles] assignment table, and the
// [[experiments]] list (P6.4), always replaced together so a Build
// never mixes generations.
type profileConfigSnapshot struct {
	master      config.CompressionConfig
	profiles    config.ProfilesConfig
	experiments []config.ExperimentConfig
}

// applyRecipeAliasToProfiles maps the deprecated `observer start
// --recipe <name>` flag onto the profiles model for THIS RUN: the
// named profile becomes the default for ALL traffic and the
// per-provider assignments are cleared — the closest honest
// equivalent of the removed daemon-wide Load() overlay (Track R,
// P2.2). Never persisted to config.toml. Unknown names error,
// preserving the old flag's loud failure. Empty name is a no-op.
//
// Behavior note vs the old overlay: profiles engage on the PROXY path
// only — recipe [compression.shell] / [compression.indexing] keys no
// longer apply to the watcher side. Operators who relied on those set
// them in config.toml directly (see CHANGELOG).
func applyRecipeAliasToProfiles(cfg *config.Config, recipeName string) error {
	if recipeName == "" {
		return nil
	}
	if _, _, err := config.LoadProfile(recipeName); err != nil {
		return err
	}
	cfg.Profiles.Default = recipeName
	cfg.Profiles.ByProvider = nil
	return nil
}

// newProfilePipeline constructs one immutable conversation pipeline
// from RESOLVED compression settings (master overlaid by a profile via
// config.ResolveCompression). Per-profile state (rolling-summary
// state, summary cache) is born here; shared infrastructure comes in
// via deps.
func newProfilePipeline(resolved config.CompressionConfig, deps profilePipelineDeps) pipelineAdapter {
	registry := conversation.BuildRegistryFromConfig(conversation.RegistryOptions{
		Logs: conversation.LogsOptions{
			MaxLines: resolved.Conversation.Logs.MaxLines,
			Head:     resolved.Conversation.Logs.Head,
			Tail:     resolved.Conversation.Logs.Tail,
		},
	})
	pipeline := conversation.NewPipeline(conversation.PipelineConfig{
		Enabled:       resolved.Conversation.Enabled,
		Mode:          resolved.Conversation.Mode,
		TargetRatio:   resolved.Conversation.TargetRatio,
		PreserveLastN: resolved.Conversation.PreserveLastN,
		CompressTypes: resolved.Conversation.CompressTypes,
		DisableDrops:  resolved.Conversation.DisableDrops,
	}, registry, deps.scrubber)
	if deps.symbolLookup != nil {
		pipeline = pipeline.WithSymbolLookup(deps.symbolLookup)
	}
	if resolved.Conversation.Stash.Enabled && deps.stash != nil {
		pipeline = pipeline.WithStash(deps.stash, resolved.Conversation.Stash.ThresholdBytes)
	}
	// Aggressive code-collapse (codeintel Phase 2) is independent of the
	// stash: when a stash is wired the collapsed body is written there for
	// retrieve_stashed; when it isn't (e.g. the codex-safe profile pins
	// stash off for OpenAI implicit-cache reasons) the collapser emits a
	// re-read marker instead. Gating is purely [codeintel].enabled +
	// .compression, so codex traffic gets collapse too. OFF by default.
	if deps.aggressiveCodeEnabled {
		pipeline = pipeline.WithAggressiveCode(true, deps.aggressiveCodeExts, deps.aggressiveCodePreview, 0)
	}
	if resolved.Conversation.Rolling.Enabled && deps.authCache != nil {
		anthFactory := messagesummary.NewFactory(deps.authCache, messagesummary.SummarizerOptions{
			Model:    resolved.Conversation.Rolling.SummaryModel,
			Recorder: deps.recorder,
		})
		oaiFactory := messagesummary.NewOpenAIFactory(deps.authCache, messagesummary.OpenAISummarizerOptions{
			Model:    resolved.Conversation.Rolling.OpenAISummaryModel,
			Recorder: deps.recorder,
		})
		pipeline = pipeline.
			WithSummarizerFactoryFor("anthropic", anthFactory, resolved.Conversation.Rolling.ThresholdTokens).
			WithSummarizerFactoryFor("openai", oaiFactory, resolved.Conversation.Rolling.ThresholdTokens)
	}
	return pipelineAdapter{p: pipeline}
}

// routerCompressor implements proxy.ClassAwareCompressor over the
// profile router: each request runs through its session's sticky
// profile pipeline, with the pidbridge-resolved tool (R2) selecting
// [profiles.by_tool] assignments ahead of per-provider ones, and the
// session CWD (R3) activating repo-local override files. Sessions the
// extractor can't resolve (empty session ID) route per-request
// against the current assignment version — deterministic, no
// stickiness needed.
type routerCompressor struct {
	r *profilerouter.Router[pipelineAdapter]
}

var _ proxy.ClassAwareCompressor = routerCompressor{}

// Compress implements proxy.Compressor (the session-less path).
func (rc routerCompressor) Compress(ctx context.Context, provider string, body []byte) proxy.CompressionResult {
	return rc.r.For(provider, "", "", "").Compress(ctx, provider, body)
}

// CompressInSession implements proxy.SessionAwareCompressor (no class
// inputs known — per-provider resolution).
func (rc routerCompressor) CompressInSession(ctx context.Context, provider string, body []byte, sessionID string) proxy.CompressionResult {
	return rc.r.For(provider, "", "", sessionID).CompressInSession(ctx, provider, body, sessionID)
}

// CompressInSessionClass implements proxy.ClassAwareCompressor
// (R2 + R3).
func (rc routerCompressor) CompressInSessionClass(ctx context.Context, class proxy.RequestClass, body []byte, sessionID string) proxy.CompressionResult {
	return rc.r.For(class.Provider, class.Tool, class.CWD, sessionID).CompressInSession(ctx, class.Provider, body, sessionID)
}

// profileKeySep separates the parts of an instance key (profile name,
// profile-file stamp, project root, project-file stamp). NUL can
// appear in none of them.
const profileKeySep = "\x00"

// profileInstanceKey builds the router instance key: the bare profile
// name when no generation data applies, else
// name SEP profileStamp SEP root SEP projectStamp — equal keys mean
// an identical resolved parameter set, and a stamp change (profile or
// project file edit) mints a new key so NEW sessions rebuild.
func profileInstanceKey(name, profileStamp, root, projectStamp string) string {
	if profileStamp == "" && root == "" && projectStamp == "" {
		return name
	}
	return name + profileKeySep + profileStamp + profileKeySep + root + profileKeySep + projectStamp
}

// splitProfileKey decodes an instance key back into profile name +
// project root ("" for plain profile-name keys).
func splitProfileKey(key string) (name, root string) {
	parts := strings.SplitN(key, profileKeySep, 4)
	if len(parts) < 3 {
		return parts[0], ""
	}
	return parts[0], parts[2]
}

// lookupProjectOverlay maps a session CWD to (project root, raw
// override file, stamp). All-empty when cwd is empty, no override
// file exists up the tree, or the file is invalid.
func lookupProjectOverlay(overlays *config.ProjectOverlays, cwd, excludeFile string) (root string, raw []byte, stamp string) {
	if cwd == "" {
		return "", nil, ""
	}
	r := config.FindProjectRoot(cwd, excludeFile)
	if r == "" {
		return "", nil, ""
	}
	b, st, ok := overlays.Lookup(r)
	if !ok {
		return "", nil, ""
	}
	return r, b, st
}
