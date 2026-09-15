// Settings section specs — mirrors the legacy SECTION_FIELDS map
// (tmp/legacy/index.html:3993-4050) so the React app can render the
// same structured form UI per section instead of a raw TOML dump.
//
// Fields are RENDERED disabled until `PUT /api/config/section/<id>`
// lands on the backend. The point of this module is to bring back
// the legacy's per-field labels + help text + option lists, which
// were lost when the static TomlView replaced the structured form.

export type FieldKind = "text" | "select" | "bool" | "int" | "list";

export type FieldDef = {
  id: string;
  label: string;
  kind: FieldKind;
  help?: string;
  // For `select`: the allowed values.
  options?: string[];
  // For `select`: resolve options dynamically from the loaded config
  // response (D11). When the named source is present it REPLACES
  // `options`; `options` stays as the static fallback for daemons
  // that don't serve the field yet.
  optionsFrom?: "profile_names";
  // For `int`: bounds + step.
  min?: number;
  max?: number;
  step?: number;
  // Opts a `select` field into rendering the RESOLVED effective mode
  // beside the raw configured value — sourced from a separate
  // GET /api/guard/prompt/detectors fetch (StructuredConfigSection
  // gates that fetch on spec.id === "prompt-detectors"), not from the
  // ConfigResponse `dynamicOptions` carry `optionsFrom` uses. The
  // field's own `id` is looked up against that response's per-detector
  // `effective_mode`. Used by the ten "prompt-detectors" section
  // fields below.
  showEffectiveMode?: boolean;
};

export type SectionSpec = {
  id: string;
  // Path into the loaded ConfigResponse.config object that holds this
  // section's live values. E.g. ["Observer", "Watch"] for the watcher
  // section. Resolved at render time. May be empty when the spec is
  // purely a parent for grouped sub-paths (see `groups` below).
  path: string[];
  description: string;
  // Flat fields. Pages with sub-objects (e.g. compression's 4 layers)
  // use `groups` instead — the renderer prefers `groups` when present.
  fields?: FieldDef[];
  // Optional nested groups — for sections whose live data lives across
  // multiple sub-objects rather than one flat record (Compression's
  // CodeGraph / Shell / Indexing / Conversation). Each group renders
  // as its own card under the section header.
  groups?: SectionGroup[];
};

export type SectionGroup = {
  id: string;
  label: string;
  // Path into the loaded config relative to the section root (or
  // absolute when the section's path is empty). E.g. ["Compression",
  // "Shell"] when iterating from the config root.
  path: string[];
  description?: string;
  fields: FieldDef[];
};

// BUILTIN_PROFILE_NAMES mirrors config.ProfileNames(): "default" +
// the embedded recipes (pinned by recipes_test.go). Since P3.4/D11
// these are only the STATIC FALLBACK for the profile selects — the
// live option list (built-ins + user profiles) comes from the
// `profile_names` field on GET /api/config via `optionsFrom`.
export const BUILTIN_PROFILE_NAMES = [
  "default",
  "claude-code",
  "codex-safe",
  "codex-variant",
];

// Each spec matches a single ConfigViewerSection route in
// Settings.tsx::sectionData(). The path[] resolves to the same object
// today's sectionData() returns.

export const SECTION_SPECS: Record<string, SectionSpec> = {
  observer: {
    id: "observer",
    path: ["Observer"],
    description:
      "Top-level observer settings - database path, log verbosity. Sub-sections (watcher / freshness / retention / hooks / antigravity) live as their own section nav entries.",
    fields: [
      {
        id: "DBPath",
        label: "DB path",
        kind: "text",
        help: "SQLite database path. Created on first run if absent.",
      },
      {
        id: "LogLevel",
        label: "Log level",
        kind: "select",
        options: ["trace", "debug", "info", "warn", "error"],
        help: "Daemon log verbosity. `info` is the recommended baseline.",
      },
    ],
  },
  watcher: {
    id: "watcher",
    path: ["Observer", "Watch"],
    description:
      "Filesystem watcher - JSONL/log file watcher. Defines what observer tails for new session activity.",
    fields: [
      {
        id: "PollIntervalSeconds",
        label: "Poll interval",
        kind: "int",
        min: 1,
        max: 60,
        help: "How often the watcher re-scans for new files (seconds).",
      },
      {
        id: "MaxFileSizeMB",
        label: "Max file size (MB)",
        kind: "int",
        min: 1,
        help: "Files larger than this are skipped to avoid OOM on rogue logs.",
      },
      {
        id: "EnabledAdapters",
        label: "Enabled adapters",
        kind: "list",
        help: "Comma-separated adapter names - claude-code, codex, cursor, cline, copilot, cowork, antigravity, opencode, openclaw, pi, gemini.",
      },
    ],
  },
  freshness: {
    id: "freshness",
    path: ["Observer", "Freshness"],
    description:
      "File-content hash engine. Used by the Discovery tab's stale-read detection.",
    fields: [
      {
        id: "EnableContentHashing",
        label: "Content hashing",
        kind: "bool",
        help: "Hash file contents to detect changes between session reads.",
      },
      {
        id: "MaxHashFileSizeMB",
        label: "Max hash file size (MB)",
        kind: "int",
        min: 1,
        help: "Files larger than this fall back to stat-only freshness.",
      },
      {
        id: "FastPathStatOnly",
        label: "Fast-path stat only",
        kind: "bool",
        help: "Skip hashing entirely; use mtime + size for change detection.",
      },
      {
        id: "IgnorePatterns",
        label: "Ignore patterns",
        kind: "list",
        help: "Globs to skip during freshness scans - node_modules, .git, etc.",
      },
    ],
  },
  retention: {
    id: "retention",
    path: ["Observer", "Retention"],
    description:
      "How long observer keeps each table's data. Pruning runs on a schedule + opportunistically on startup.",
    fields: [
      {
        id: "MaxAgeDays",
        label: "Max age (days)",
        kind: "int",
        min: 1,
        help: "Actions / token rows older than this are vacuumed.",
      },
      {
        id: "MaxDBSizeMB",
        label: "Max DB size (MB)",
        kind: "int",
        min: 1,
        help: "Soft cap on the SQLite database - pruning triggers above.",
      },
      {
        id: "PruneOnStartup",
        label: "Prune on startup",
        kind: "bool",
        help: "Run the prune sweep when the daemon starts.",
      },
      {
        id: "ObserverLogMaxAgeDays",
        label: "Observer log max age (days)",
        kind: "int",
        min: 1,
        help: "Lifetime of the daemon's own log file.",
      },
    ],
  },
  hooks: {
    id: "hooks",
    path: ["Observer", "Hooks"],
    description:
      "Per-tool hook configuration. The daemon installs lightweight stop-hooks into each AI client to capture turn boundaries.",
    fields: [
      {
        id: "TimeoutMS",
        label: "Hook timeout (ms)",
        kind: "int",
        min: 50,
        max: 30_000,
        help: "How long the hook is allowed to run before the client gives up on it. Keep low - the hook is on the user's latency budget.",
      },
      {
        id: "AutoRegister",
        label: "Auto-register on start",
        kind: "bool",
        help: "Re-register hooks for every detected AI tool each time `observer start` launches. Idempotent and conflict-safe: user-authored hook entries are never overwritten. Turn off to manage hook registration manually via `observer init`.",
      },
    ],
  },
  browser: {
    id: "browser",
    path: ["Browser"],
    description:
      "Browser-chat capture (opt-in MV3 extension → chatgpt-web / claude-web / perplexity-web / gemini-web / copilot-web). The granularity ceiling is the daemon's §5.1 clamp: the maximum a captured turn is stored at, regardless of what the extension sent. usage_only = counts + model + latency only (no prompt/response text); redacted = client-redacted content; full = raw content (still passes the server scrub seam). Lower the ceiling to keep on-screen text out of the DB while still tracking tokens and cost.",
    fields: [
      {
        id: "GranularityCeiling",
        label: "Granularity ceiling",
        kind: "select",
        options: ["usage_only", "redacted", "full"],
        help: "Maximum stored capture granularity. The effective granularity of any turn is min(what the extension sent, this ceiling). Prompt/response text is stored only at redacted or full.",
      },
    ],
  },
  terminal: {
    id: "terminal",
    path: ["Terminal", "Attach"],
    description:
      "Session attach ([terminal.attach]) - jump into a running `observer <tool> --attach` session from the dashboard, and route attach sessions through the observer proxy. The attach control channel is an owner-only AF_UNIX socket (mode 0600), never network-reachable. Restart semantics differ per field: serving the socket binds at daemon start (restart required), while route-through-proxy is read per-launch (no restart) - the save reports a restart only when it's actually needed.",
    fields: [
      {
        id: "Enabled",
        label: "Serve attach socket",
        kind: "bool",
        help: "Serve the attach socket so `observer <tool> --attach` can hand its terminal to the daemon (making it joinable from the dashboard). Restart required - the socket is bound when the daemon starts.",
      },
      {
        id: "RouteProxy",
        label: "Route through proxy",
        kind: "bool",
        help: "Attach sessions route through the observer proxy by default (so they capture tokens through :8820); disable to launch attach sessions with --no-proxy-route semantics. Read per-launch by the CLI - a change takes effect on the NEXT attach launch, no daemon restart needed.",
      },
      {
        id: "DefaultOn",
        label: "Attach by default",
        kind: "bool",
        help: "The `observer claude` / `observer codex` launchers attach to a live session by default; opt out per-launch with --no-attach. Read per-launch by the CLI - a change takes effect on the NEXT launch, no daemon restart needed.",
      },
    ],
  },
  antigravity: {
    id: "antigravity",
    path: ["Observer", "Antigravity"],
    description:
      "Antigravity (Google) adapter config. The bridge mode controls how the Windows-side .pb files are reached when observer runs under WSL2.",
    fields: [
      {
        id: "NetworkRecovery",
        label: "Network recovery",
        kind: "select",
        options: ["off", "local"],
        help: "off = no recovery, fails on missing files. local = use a Windows-side bridge helper for cross-mount filesystem access. See the helper card below for setup.",
      },
    ],
  },
  process: {
    id: "process",
    path: ["Observer", "Process"],
    description:
      "OS-level process observability (opt-in). Captures process trees launched by AI tools and attributes them to sessions. The poll rate is the single knob that controls how often every process source - the Linux /proc poll and the Windows cross-OS bridge - is sampled.",
    groups: [
      {
        id: "process-capture",
        label: "Process table",
        path: ["Observer", "Process"],
        description:
          "Live OS process rows. Backfill cannot reconstruct these rows from old transcripts.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Master switch for process capture. Default off. When off, zero process backends are constructed and no process_runs/process_events rows are written.",
          },
          {
            id: "Backend",
            label: "Backend",
            kind: "select",
            options: [
              "auto",
              "both",
              "poll",
              "bridge",
              "linux_ebpf",
              "etw",
              "endpointsecurity",
              "off",
            ],
            help: "Capture source. `auto` picks the best available (on WSL with a Windows observer.exe it runs the Linux poll AND the Windows bridge together). `both` forces that composite explicitly; `poll` is Linux /proc only; `bridge` is the Windows cross-OS bridge only.",
          },
          {
            id: "PollIntervalMS",
            label: "Poll rate (ms)",
            kind: "int",
            min: 0,
            max: 600000,
            step: 250,
            help: "How often the process table is snapshotted, in milliseconds, for BOTH the Linux poll backend and the Windows bridge. Default 2000 (2s). 0 inherits the default. Lower = fresher capture + more CPU; higher = cheaper but more likely to miss commands that start and exit inside one interval.",
          },
          {
            id: "BridgePollIntervalMS",
            label: "Bridge poll override (ms)",
            kind: "int",
            min: 0,
            max: 600000,
            step: 250,
            help: "Optional per-bridge override of the poll rate for the Windows cross-OS bridge only. 0 = inherit the poll rate above (leave at 0 unless you want the Windows bridge to sample at a different cadence than the Linux poll).",
          },
          {
            id: "CaptureUnattributed",
            label: "Capture unattributed",
            kind: "bool",
            help: "Persist process rows that could not be joined to a session. Default off (unattributed processes are counted for health only, to bound the privacy blast radius).",
          },
        ],
      },
      {
        id: "network-capture",
        label: "Network capture",
        path: ["Observer", "Process", "Network"],
        description:
          "Network events for AI-tool sessions. Body excerpts are only available for SuperBased-proxied/plaintext flows; non-proxied TLS remains metadata-only.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Records network_connect events for attributed sessions, including SuperBased proxy calls. Required for the session API/network calls table.",
          },
          {
            id: "CaptureBodies",
            label: "Body capture",
            kind: "select",
            options: ["off", "proxied", "available"],
            help: "`off` stores metadata only. `proxied` stores capped/scrubbed excerpts for SuperBased proxy flows. `available` is reserved for future plaintext/instrumented backends.",
          },
          {
            id: "MaxRequestBytes",
            label: "Max request bytes",
            kind: "int",
            min: 0,
            max: 1048576,
            step: 1024,
            help: "Maximum stored request-body excerpt size. 0 stores no request excerpt.",
          },
          {
            id: "MaxResponseBytes",
            label: "Max response bytes",
            kind: "int",
            min: 0,
            max: 1048576,
            step: 1024,
            help: "Maximum stored response-body excerpt size. 0 stores no response excerpt.",
          },
          {
            id: "CaptureHeaders",
            label: "Capture headers",
            kind: "bool",
            help: "Store the scrubbed header allowlist with captured body rows. Authorization-style headers are excluded.",
          },
          {
            id: "ScrubBodies",
            label: "Scrub bodies",
            kind: "bool",
            help: "Run body excerpts through the secret scrubber before storage.",
          },
          {
            id: "CaptureRemoteHost",
            label: "Capture remote host",
            kind: "bool",
            help: "Store the resolved remote host when available.",
          },
          {
            id: "RedactPrivateIPs",
            label: "Redact private IPs",
            kind: "bool",
            help: "Suppress RFC1918 and loopback destinations from stored network metadata.",
          },
          {
            id: "StoreBinary",
            label: "Store binary",
            kind: "bool",
            help: "Allow binary/non-text bodies to be converted into excerpts. Leave off unless you need this diagnostic detail.",
          },
        ],
      },
      {
        id: "etw",
        label: "Elevated ETW capturer (Windows)",
        path: ["Observer", "Process", "ETW"],
        description:
          "The daemon-side ACCEPT listener that the elevated Windows ETW capturer dials into. It is what makes per-process NETWORK BYTES available: ETW session control always requires elevation, so the capturer runs as a Scheduled Task and connects here. Additive - with it off, everything else captures exactly as before. Windows/WSL only. The shared token is deliberately NOT editable here: it gates a loopback port that WSL2 exposes to the whole Windows host, and leaving it empty (the default) lets the daemon generate and persist one at the token path below. The setup card underneath registers the Scheduled Task for you.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Starts the accept listener. Default off - it opens a port, and the feed behind it needs an elevated Windows Scheduled Task. Binds at daemon start, so a change needs a restart.",
          },
          {
            id: "ListenAddr",
            label: "Listen address",
            kind: "text",
            help: "Loopback bind for the capturer's inbound connection, as host:port. Empty inherits 127.0.0.1:8823. The capturer dials IN (WSL cannot reach a Windows-bound listener, but Windows→WSL loopback works), so this address is baked into the Scheduled Task - changing it means re-registering the task.",
          },
          {
            id: "TokenPath",
            label: "Token file path",
            kind: "text",
            help: "Where a generated shared token is persisted 0600. Empty puts `process-bridge-token` next to the observer DB. The elevated capturer reads it with --token-file, so on WSL it must be a path Windows can open (the setup card's command handles the \\\\wsl.localhost translation).",
          },
          {
            id: "HandshakeTimeoutMS",
            label: "Handshake timeout (ms)",
            kind: "int",
            min: 0,
            max: 600000,
            step: 1000,
            help: "Bounds the authentication exchange only - an authenticated stream is legitimately idle for long stretches and is never deadlined. Default 10000 (10s); 0 inherits it.",
          },
          {
            id: "AllowNonLoopback",
            label: "Allow non-loopback bind",
            kind: "bool",
            help: "Permits binding the listener to a non-loopback address. Default off, and the listener refuses one otherwise. Leave off: even the loopback bind is reachable from every process on the Windows host under WSL2 localhostForwarding, which is why the shared token is load-bearing.",
          },
        ],
      },
    ],
  },
  advisor: {
    id: "advisor",
    path: ["Advisor"],
    description:
      "The suggestions engine behind the Suggestions tab, `observer advise`, and the get_suggestions MCP tool. Evidence windows, visibility floors, and the opt-in session-start digest.",
    fields: [
      {
        id: "Enabled",
        label: "Enabled",
        kind: "bool",
        help: "Master switch for the suggestions engine. Default on - detectors run read-only over already-captured data at request time (no LLM calls, no extra capture).",
      },
      {
        id: "WindowDays",
        label: "Evidence window (days)",
        kind: "int",
        min: 1,
        max: 365,
        help: "Default lookback for detectors when no explicit window is requested. Default 14.",
      },
      {
        id: "MinConfidence",
        label: "Min confidence",
        kind: "int",
        min: 0,
        max: 1,
        step: 0.05,
        help: "Suggestions below this confidence floor are hidden everywhere (0–1). Default 0.5.",
      },
      {
        id: "MinSavingsUSD",
        label: "Min savings (USD)",
        kind: "int",
        min: 0,
        step: 0.5,
        help: "Cost suggestions claiming less than this are hidden - keeps the tab from nagging about pennies. Default 1.",
      },
      {
        id: "SessionDigest",
        label: "Session-start digest",
        kind: "bool",
        help: "Inject a small advisory digest (top suggestions, ≤400 tokens) into Claude Code at session start. The hook only reads a cached snapshot - it never computes on your session's critical path. Default off.",
      },
      {
        id: "DigestRefreshMinutes",
        label: "Digest refresh (minutes)",
        kind: "int",
        min: 5,
        max: 1440,
        help: "How often the daemon refreshes the digest snapshot the session-start hook reads. Default 30.",
      },
    ],
  },
  cachetrack: {
    id: "cachetrack",
    path: ["CacheTrack"],
    description:
      "Anthropic prompt-cache observation + forecasting - the Cache tab's data source. Hash-only and node-local: cache rows never leave this machine.",
    fields: [
      {
        id: "Enabled",
        label: "Enabled",
        kind: "bool",
        help: "Observe cache behavior on proxied traffic (Tier 1) and transcripts (Tier 2). Default on. Historical sessions can be retrofitted via Backfill → cache-rescan.",
      },
      {
        id: "MaxTrackedSessions",
        label: "Max tracked sessions",
        kind: "int",
        min: 0,
        help: "LRU bound on the engine's per-session cache models. 0 = unbounded (not recommended). Default 64.",
      },
      {
        id: "RetentionDays",
        label: "Retention (days)",
        kind: "int",
        min: 0,
        help: "Days to keep cache_segments / cache_entries / cache_events rows. 0 = never prune. Default 90.",
      },
      {
        id: "CalibrateLogPath",
        label: "Calibrate log path",
        kind: "text",
        help: "Diagnostic sidecar: when set, per-block JSON lines are written to this file (auto-stops after ~200 blocks). Leave empty unless debugging cache attribution.",
      },
    ],
  },
  tasks: {
    id: "tasks",
    path: ["Tasks"],
    description:
      "Session-level todo/plan checklist tracking (docs/task-tracking.md) — decodes claude-code TaskCreate/TaskUpdate/TodoWrite, codex update_plan, kiro-cli todo_list, copilot manage_todo_list, and similar tool calls already captured in actions.raw_tool_input into a per-task lifecycle + cost report (the Tasks tab, and the Analysis page's Tasks section). No new capture surface, no adapter change. A change here needs a daemon restart to take effect — [tasks] has no hot-reload path yet (SetTasksEnabled/SetTasksOptions bind once at daemon startup, the same posture every section except pricing/profiles has).",
    fields: [
      {
        id: "Enabled",
        label: "Enabled",
        kind: "bool",
        help: "Decode todo/plan tool calls into task_items/task_transitions as they're captured. Default on. Disabling makes the task-tracking ingest pass a pure no-op; historical rows already decoded stay in the DB. Retrofit history after enabling with `observer backfill --tasks`.",
      },
      {
        id: "MatchMode",
        label: "Match mode",
        kind: "select",
        options: ["exact", "normalized"],
        help: "How whole-list-rewrite tools (no vendor item id) are matched across consecutive snapshot calls. `exact` (default) matches the trimmed content string verbatim — a fuzzy match would trade a known, countable loss for an unknown, silent mis-join. `normalized` additionally lowercases and collapses whitespace, tolerating cosmetic re-wording at the cost of possibly merging two different items whose text happens to normalize the same.",
      },
      {
        id: "ConcurrentAttribution",
        label: "Concurrent attribution",
        kind: "select",
        options: ["shared", "none"],
        help: "How a token/action row is bucketed when two or more tasks are in_progress at once. `shared` (default) buckets the row into a per-session `shared` total rather than splitting it evenly or picking a dominant task — either would invent a precision the data doesn't contain. `none` drops the row from every task's total instead (still counted overall, just not attributed to a specific task) for an operator who'd rather under-report than see a shared bucket.",
      },
      {
        id: "IncludeSidechains",
        label: "Include sidechains",
        kind: "bool",
        help: "Fold a spawned sub-agent's own token/action rows into whichever task happened to be open in the PARENT session at the same wall-clock time. Default off — sub-agent usage is reported as its own separate `sidechain` total instead, since a TaskUpdate's owner field is free text and can't be resolved to the actual spawned session.",
      },
      {
        id: "BackfillOnStart",
        label: "Backfill on start",
        kind: "bool",
        help: "Re-derive task_items/task_transitions from historical actions rows once at daemon startup (the same work as `observer backfill --tasks`, run automatically). Default off — run the CLI flag by hand after enabling this section on a daemon with historical task-tool traffic. Idempotent.",
      },
      {
        id: "RetentionDays",
        label: "Retention (days)",
        kind: "int",
        min: 0,
        help: "Days to keep task_items/task_transitions rows. 0 = never prune (the default — no pruning sweep ships yet; this field exists so one has a home without a future config-shape change).",
      },
    ],
  },
  observability: {
    id: "observability",
    path: ["Observability"],
    description:
      "Generalized observability subsystem (admin plane) - the OTLP /v1/traces receiver, trajectory capture, and the eval plane for an admin/org-hosted LLM app whose end-users route through SuperBased. Distinct from your own coding-agent usage; the captured data is viewed on the admin/org dashboard. Opt-in and node-local: trace data never leaves this machine unless an obs share tier is enabled. The receiver binds at daemon start, so enabling here needs a restart to take effect. Note the receiver is SHARED with the log-ingest path - it also comes alive whenever [ingest.otel] is enabled, so this toggle is not the only thing that binds :4317/:4318.",
    fields: [
      {
        id: "Enabled",
        label: "Enabled",
        kind: "bool",
        help: "Turn on the obs subsystem: the OTLP trace receiver (gRPC :4317 / HTTP :4318), the obs_* schema, trajectory ingestion + API, and the eval plane. Default off. The receiver is shared with [ingest.otel] (logs), so it may already be bound from that toggle. The judge model + online-sampling eval config ([observability.eval]) stays a hand-edited config decision.",
      },
    ],
  },
  secrets: {
    id: "secrets",
    path: ["Observer", "Secrets"],
    description:
      "Secret scrubbing applied to captured tool output BEFORE anything is written to the database. Built-in patterns cover common API-key and token shapes.",
    fields: [
      {
        id: "EnableScrubbing",
        label: "Scrubbing",
        kind: "bool",
        help: "Redact known secret shapes (API keys, bearer tokens, connection strings) from captured output before storage. Default on - turn off only if you fully control the database.",
      },
      {
        id: "ExtraPatterns",
        label: "Extra patterns",
        kind: "list",
        help: "Additional regex patterns to redact, comma-separated - e.g. org-internal token prefixes or hostnames. Appended to the built-in set.",
      },
    ],
  },
  compression: {
    id: "compression",
    // Saving POSTs the section root to PUT /api/config/section/compression
    // which decodes the body as config.CompressionConfig. The body keys
    // therefore have to be {CodeGraph, Shell, Indexing, Conversation}
    // at the top level — i.e. spec.path must root at ["Compression"].
    // An empty spec.path here (the prior shape) made draft = the whole
    // root config and every Save zeroed cfg.Compression server-side.
    // Group paths INCLUDE the section prefix (the renderer strips
    // spec.path.length elements) — same convention as profiles'
    // ["Profiles","ByProvider"]. They briefly lacked it after the
    // spec.path fix, which left every group control resolving against
    // the wrong object (D14).
    path: ["Compression"],
    description:
      "Three live compression layers - shell output filters, FTS5 tool-output indexing, and conversation-level compression (with stash / rolling-summarisation / compaction sub-toggles). Each layer toggles independently; defaults err on the side of safety. (Code-graph integration is configured under Settings → Intelligence per the v1.4.20 audit - the compression.code_graph fields had no Go consumers and were removed.)",
    groups: [
      {
        id: "shell",
        label: "Shell output",
        path: ["Compression", "Shell"],
        description:
          "RTK-style filters that strip noise (ANSI escapes, progress bars, repetitive output) from captured shell command output.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Master toggle for shell output filtering.",
          },
          {
            id: "ExcludeCommands",
            label: "Exclude commands",
            kind: "list",
            help: "Comma-separated list of commands whose output is never filtered.",
          },
        ],
      },
      {
        id: "indexing",
        label: "Tool output indexing",
        path: ["Compression", "Indexing"],
        description:
          "Index large tool-call outputs in an FTS5 table so the MCP search_past_outputs can retrieve them on demand without bloating the conversation.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Master toggle for FTS5 indexing of tool outputs.",
          },
          {
            id: "MaxExcerptBytes",
            label: "Max excerpt bytes",
            kind: "int",
            min: 256,
            help: "Truncate excerpts beyond this byte count.",
          },
          {
            id: "Embeddings",
            label: "Embeddings (experimental - not yet wired)",
            kind: "bool",
            help: "Reserved for semantic embeddings on indexed excerpts. No Go consumer reads this flag today; toggling has no effect. Kept for forward-compat with the indexing pipeline.",
          },
        ],
      },
      {
        id: "conversation",
        label: "Conversation",
        path: ["Compression", "Conversation"],
        description:
          "Per-turn conversation-level compression. The mode controls how aggressively prior turns are pruned vs. cached. cache_aware preserves Anthropic's prefix cache for Pro/Max users.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Master toggle for conversation compression.",
          },
          {
            id: "Mode",
            label: "Mode",
            kind: "select",
            options: ["token", "cache", "cache_aware"],
            help: "token = legacy drop ranking; cache = restrict drops to tail half + inject cache_control; cache_aware = no drops (preserves Anthropic prefix cache).",
          },
          {
            id: "TargetRatio",
            label: "Target ratio",
            kind: "text",
            help: "Compression target as a fraction (0..1). e.g. 0.5 = compress to half input tokens.",
          },
          {
            id: "PreserveLastN",
            label: "Preserve last N",
            kind: "int",
            min: 0,
            help: "Always keep this many of the most-recent messages uncompressed.",
          },
          {
            id: "CompressTypes",
            label: "Compress types",
            kind: "list",
            help: "Role-types eligible for compression. Empty = all.",
          },
        ],
      },
      {
        id: "stash",
        label: "Stash (SROD)",
        path: ["Compression", "Conversation", "Stash"],
        description:
          "Stash & Retrieve on Demand - write large tool_result bodies to a content-addressed on-disk stash and replace inline with a SHA marker. The model retrieves originals via the `retrieve_stashed` MCP tool.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Master toggle for the stash layer.",
          },
          {
            id: "Dir",
            label: "Stash dir",
            kind: "text",
            help: "Where stashed bodies live on disk. Default: ~/.observer/stash.",
          },
          {
            id: "ThresholdBytes",
            label: "Threshold bytes",
            kind: "int",
            min: 512,
            help: "Tool_result bodies above this size get stashed.",
          },
          {
            id: "MaxTotalMB",
            label: "Max total (MB)",
            kind: "int",
            min: 1,
            help: "Soft cap on total stash dir size - older entries evict above this.",
          },
        ],
      },
      {
        id: "rolling",
        label: "Rolling summarisation",
        path: ["Compression", "Conversation", "Rolling"],
        description:
          "When a session crosses the threshold the proxy summarises older messages inline. Independent summary models per Anthropic + OpenAI traffic.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Master toggle for rolling summarisation.",
          },
          {
            id: "ThresholdTokens",
            label: "Threshold tokens",
            kind: "int",
            min: 1024,
            help: "Sessions crossing this many tokens trigger rolling summarisation.",
          },
          {
            id: "SummaryModel",
            label: "Anthropic summary model",
            kind: "text",
            help: "Default: claude-haiku-4-5.",
          },
          {
            id: "OpenAISummaryModel",
            label: "OpenAI summary model",
            kind: "text",
            help: "Default: gpt-5-nano.",
          },
        ],
      },
      {
        id: "compaction",
        label: "Compaction recovery",
        path: ["Compression", "Conversation", "Compaction"],
        description:
          "After a compaction event the proxy can inject a synthetic system block carrying recovery context (recent reads, edits, failures, learned rules) so the model can re-orient.",
        fields: [
          {
            id: "InjectPostCompact",
            label: "Inject post-compact context",
            kind: "bool",
            help: "Surface recovery context after compaction events.",
          },
        ],
      },
    ],
  },
  proxy: {
    id: "proxy",
    path: ["Proxy"],
    description:
      "API proxy listener. The proxy intercepts Anthropic / OpenAI / Google API calls from your AI client, captures the exact request/response bodies, then forwards upstream - giving the dashboard ground-truth token + cost accounting.",
    fields: [
      {
        id: "Enabled",
        label: "Proxy enabled",
        kind: "bool",
        help: "If false, no HTTP listener binds. Hook-only capture continues to work.",
      },
      {
        id: "Port",
        label: "Listen port",
        kind: "int",
        min: 1024,
        max: 65_535,
        help: "TCP port the proxy listens on. Default 8820.",
      },
      {
        id: "AnthropicUpstream",
        label: "Anthropic upstream",
        kind: "text",
        help: "Base URL for Anthropic requests. Default https://api.anthropic.com.",
      },
      {
        id: "OpenAIUpstream",
        label: "OpenAI upstream",
        kind: "text",
        help: "Base URL for OpenAI-compatible requests. Default https://api.openai.com.",
      },
      {
        id: "ChatGPTUpstream",
        label: "ChatGPT upstream",
        kind: "text",
        help: "Base URL for ChatGPT-plan Codex backend requests. Default https://chatgpt.com.",
      },
      {
        id: "ForceChatGPTHTTP",
        label: "Force ChatGPT HTTP",
        kind: "bool",
        help: "Reject ChatGPT Codex websocket upgrades so the client falls back to HTTPS POST requests (which the proxy can compress).",
      },
    ],
  },
  dashboard: {
    id: "dashboard",
    path: ["Dashboard"],
    description:
      "Durable listen address for the local analytics dashboard. Set this to survive daemon/service restarts without the per-run --dashboard-addr flag (wanted for launchd/systemd units and port-8081 conflicts). Precedence: the --dashboard-addr flag > the OBSERVER_DASHBOARD_ADDR env var > this config value > the built-in 127.0.0.1:8081 default. The dashboard listener binds at daemon start, so a save here needs a restart to take effect. A non-loopback address does NOT bypass the remote-exposure guard - it still fails closed unless the [remote] security substrate is armed.",
    fields: [
      {
        id: "Addr",
        label: "Listen address",
        kind: "text",
        help: "host:port for the dashboard listener (e.g. 127.0.0.1:8082). Empty = the built-in 127.0.0.1:8081 default. Validated as host:port at daemon start.",
      },
    ],
  },
  profiles: {
    id: "profiles",
    path: ["Profiles"],
    description:
      "Which compression profile each traffic class runs. Profiles are named parameter sets (the embedded recipes plus `default` = your master compression settings) resolved per request at the proxy - so Claude Code and codex each get their tuned parameters from one daemon. The master Compression → Conversation `enabled` switch stays the only on/off gate; profiles never turn compression on.",
    fields: [
      {
        id: "Default",
        label: "Default profile",
        kind: "select",
        options: BUILTIN_PROFILE_NAMES,
        optionsFrom: "profile_names",
        help: "Profile for traffic no per-provider assignment matches. `default` = master config parameters.",
      },
    ],
    groups: [
      {
        id: "by_provider",
        label: "Per-provider assignments",
        path: ["Profiles", "ByProvider"],
        description:
          "Resolved from the request path: Anthropic Messages API traffic vs OpenAI-path traffic. Saves apply to NEW sessions immediately - in-flight sessions keep the parameters they started with (no restart needed).",
        fields: [
          {
            id: "anthropic",
            label: "Anthropic traffic",
            kind: "select",
            options: BUILTIN_PROFILE_NAMES,
            optionsFrom: "profile_names",
            help: "Claude Code and any client on the Anthropic Messages API path. Tuned default: claude-code (cache-aware - won't break Anthropic prompt caching).",
          },
          {
            id: "openai",
            label: "OpenAI traffic",
            kind: "select",
            options: BUILTIN_PROFILE_NAMES,
            optionsFrom: "profile_names",
            help: "codex and any client on the OpenAI paths. Tuned default: codex-safe (logs compression + tool-defs trim). Running a *-codex reasoning model? Assign codex-variant.",
          },
        ],
      },
    ],
  },
  org: {
    id: "org",
    // PUT /api/config/section/org decodes OrgClientConfig but the
    // server copies ONLY Share/Scope/PushIntervalSeconds/MaxPushBytes
    // — the enrolment identity (enabled, org_server_url, keychain_id)
    // is owned by `observer enroll` and a section save can never
    // touch it (test-pinned).
    path: ["OrgClient"],
    description:
      "What this node shares with your organisation's SuperBased server - and only when enrolled ([org_client] enabled via `observer enroll`; see the Enrolment section). The privacy default is metadata-only: sha256 hashes and counts, never raw commands, prose, or paths. Raw-content sharing (full_content) is node opt-in only - the org admin has no remote switch for it. The reporting-tier shares below (routing_summary, obs_summary, etc.) are node opt-in, or can be raised by the org on a managed node via node governance policy.",
    fields: [
      {
        id: "PushIntervalSeconds",
        label: "Push interval (seconds)",
        kind: "int",
        min: 60,
        help: "Cadence of the push loop. Default 900 (15 minutes).",
      },
      {
        id: "MaxPushBytes",
        label: "Max push batch (bytes)",
        kind: "int",
        min: 65536,
        help: "Uncompressed JSON ceiling per batch. Default 1 MiB; clamped to 16 MiB.",
      },
    ],
    groups: [
      {
        id: "share",
        label: "Share mode",
        path: ["OrgClient", "Share"],
        description:
          "The v1.8.0 content posture. OFF (default): only sha256 hashes and counts cross the wire - raw command bodies, assistant prose, and filesystem paths are stripped at the SQL seam. These switches live in THIS node's config file only; no server can flip them.",
        fields: [
          {
            id: "FullContent",
            label: "Share full content",
            kind: "bool",
            help: "Ship raw command bodies, assistant prose, and raw paths alongside the hashes. Off = metadata-only (the default posture). Think before enabling: everything shipped is visible to your org admins.",
          },
          {
            id: "TargetActionAllowlist",
            label: "Per-action target allowlist",
            kind: "list",
            help: "Cautious middle ground: ship the raw target column ONLY for these action types (e.g. read_file, edit_file, write_file) while withholding commands and prose. Empty = no exception.",
          },
        ],
      },
      {
        id: "scope",
        label: "Project scope",
        path: ["OrgClient", "Scope"],
        description:
          "Which projects push at all, by exact root path. Both lists are node-side config; denylist applies after allowlist.",
        fields: [
          {
            id: "ProjectRootAllowlist",
            label: "Project allowlist",
            kind: "list",
            help: "When non-empty, ONLY these project roots push. Empty = all projects.",
          },
          {
            id: "ProjectRootDenylist",
            label: "Project denylist",
            kind: "list",
            help: "These project roots never push.",
          },
        ],
      },
    ],
  },
  otel: {
    id: "otel",
    path: ["Exporter", "OTel"],
    description:
      "Agent-side OpenTelemetry exporter: one gen_ai.client span per proxied API turn to any OTLP/HTTP collector. Off by default - when disabled the daemon makes zero exporter network calls. OTEL_* environment variables override these file values.",
    fields: [
      {
        id: "Enabled",
        label: "Enabled",
        kind: "bool",
        help: "Start the exporter goroutine. Off = zero OTLP network calls.",
      },
      {
        id: "Endpoint",
        label: "Collector endpoint",
        kind: "text",
        help: "OTLP/HTTP collector as host:port (no scheme, no path). Default localhost:4318.",
      },
      {
        id: "Insecure",
        label: "Plain HTTP",
        kind: "bool",
        help: "Send over HTTP instead of HTTPS. For local collectors only.",
      },
      {
        id: "PollIntervalSeconds",
        label: "Poll interval (seconds)",
        kind: "int",
        min: 1,
        help: "Row-tail poll cadence against api_turns. Default 1.",
      },
      {
        id: "EmitPromptContent",
        label: "Emit prompt content",
        kind: "bool",
        help: "Attach prompt/completion bodies to spans. Default off - real privacy and data-volume implications; read the exporter docs before enabling.",
      },
      {
        id: "EmitUserEmail",
        label: "Emit user email",
        kind: "bool",
        help: "Attach sbo.user.email when enrolled, for per-developer slicing in your own backend. Default off.",
      },
    ],
  },
  guard: {
    id: "guard",
    // PUT /api/config/section/guard decodes config.GuardConfig, so the
    // spec roots at ["Guard"] and group paths include that prefix (the
    // strip convention — see compression). [guard.cloud] is deliberately
    // ABSENT: network egress opt-ins stay a hand-written config decision
    // (D1 posture) and the backend preserves the prior Cloud block on
    // every save. Rules.OrgBundle + Rules.CEL likewise survive saves
    // untouched server-side.
    path: ["Guard"],
    description:
      "Security guard layer - posture, rule tuning, taint tracking, proxy scans, MCP pinning, budgets, and alerts. Everything here binds at daemon start (restart banner after save). Moving to enforce? Use the Security page's mode control - it shows what would have blocked first.",
    fields: [
      {
        id: "Enabled",
        label: "Enabled",
        kind: "bool",
        help: "Master gate for all guard wiring (hook seam, proxy seams, ingest flagging, guard_events). Off = no policy engine is constructed.",
      },
      {
        id: "Mode",
        label: "Mode",
        kind: "select",
        options: ["off", "observe", "enforce"],
        help: "observe (default) records and alerts but never blocks; enforce lets deny/ask-class rules actually block at the hook + proxy seams.",
      },
      {
        id: "Strict",
        label: "Strict (fail-closed)",
        kind: "bool",
        help: "A guard-internal error then blocks instead of approving. Enterprise posture; default off (fail-open).",
      },
      {
        id: "RetentionDays",
        label: "Retention (days)",
        kind: "int",
        min: 0,
        help: "Prune horizon for guard events + expired approvals. Audit data wants ≥365 for compliance. 0 disables the guard prune.",
      },
    ],
    groups: [
      {
        id: "rules",
        label: "Rules",
        path: ["Guard", "Rules"],
        description:
          "Rule disables + policy-file locations. The org bundle path and the CEL v2 gate are managed outside this form and survive saves.",
        fields: [
          {
            id: "Disable",
            label: "Disabled rule IDs",
            kind: "list",
            help: "Rule IDs turned off entirely (e.g. R-151). Prefer a scoped approval or a policy override first - disables are global and unconditional.",
          },
          {
            id: "UserPolicy",
            label: "User policy file",
            kind: "text",
            help: "Your [[rule]]/[[override]] policy file. Empty = ~/.observer/guard-policy.toml.",
          },
          {
            id: "ProjectPolicy",
            label: "Project policy file",
            kind: "text",
            help: "Per-project policy path relative to each project root. Empty = .observer/guard-policy.toml. Project layers can only ESCALATE.",
          },
        ],
      },
      {
        id: "boundary",
        label: "Boundary",
        path: ["Guard", "Boundary"],
        description:
          "Write/read boundary allowlists. EMPTY here means 'keep the engine defaults' - an explicit 'no allowlist at all' is a config-file edit (the form can't express the difference).",
        fields: [
          {
            id: "AllowPaths",
            label: "Allowed paths",
            kind: "list",
            help: "Glob patterns the boundary rules (R-15x) treat as in-bounds - e.g. ../sibling-project/**. Empty = engine defaults.",
          },
          {
            id: "ProtectedBranches",
            label: "Protected branches",
            kind: "list",
            help: "Branches R-110/R-111 protect from force-push / deletion. Empty = engine defaults (main, master, …).",
          },
        ],
      },
      {
        id: "taint",
        label: "Taint tracking",
        path: ["Guard", "Taint"],
        description:
          "Session-level untrusted-source marks (web fetches, unpinned MCP, external files). The T-5xx rules fire when tainted sessions cross dangerous sinks.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Off = the taint snapshot is always empty and T-5xx rules never fire.",
          },
          {
            id: "DecayTurns",
            label: "Decay (turns)",
            kind: "int",
            min: 1,
            help: "How many session turns a taint mark lives. Default 10.",
          },
        ],
      },
      {
        id: "proxy",
        label: "Proxy scans",
        path: ["Guard", "Proxy"],
        description:
          "Request/response inspection on the API proxy path. Only engages for traffic routed through the proxy.",
        fields: [
          {
            id: "EgressScan",
            label: "Egress secret scan",
            kind: "bool",
            help: "Scan outbound request bodies for typed secrets (R-172). Default on.",
          },
          {
            id: "EgressAction",
            label: "Egress action (enforce)",
            kind: "select",
            options: ["flag", "mask", "deny"],
            help: "What an enforce-mode egress hit does: flag = record only, mask = rewrite detector-certain values to [REDACTED:type] and forward, deny = synthetic 403. Observe mode always just flags.",
          },
          {
            id: "EgressAllow",
            label: "Egress allow patterns",
            kind: "list",
            help: "Regexes over the MATCHED VALUE - findings matching these are ignored (test fixtures, known-fake keys).",
          },
          {
            id: "ResponseScan",
            label: "Response scan",
            kind: "bool",
            help: "Inspect tool_use responses (flag/alert only in v1). Default on.",
          },
          {
            id: "InjectionHeuristics",
            label: "Injection heuristics",
            kind: "bool",
            help: "Flag prompt-injection shapes in inbound tool results / web content (flag + taint, never deny). Default on.",
          },
        ],
      },
      {
        id: "mcp",
        label: "MCP security",
        path: ["Guard", "MCP"],
        description:
          "Tool pinning + poisoning detection for MCP servers seen in your AI clients' configs (R-301…R-305).",
        fields: [
          {
            id: "Pinning",
            label: "Pinning",
            kind: "bool",
            help: "Track MCP server identity; a new or changed server raises R-301/R-302 until approved. Default on.",
          },
          {
            id: "PoisoningHeuristics",
            label: "Poisoning heuristics",
            kind: "bool",
            help: "Description-pattern checks for tool-poisoning shapes (R-303). Default on.",
          },
        ],
      },
      {
        id: "budget",
        label: "Budgets",
        path: ["Guard", "Budget"],
        description:
          "Cost circuit-breakers (B-601/B-602). 0 = off. These are guard-rule limits - the advisory monthly budgets live under Settings → Intelligence.",
        fields: [
          {
            id: "SessionUSD",
            label: "Per-session limit (USD)",
            kind: "int",
            min: 0,
            step: 0.5,
            help: "B-601 fires when one session's spend crosses this. 0 disables.",
          },
          {
            id: "DailyUSD",
            label: "Daily limit (USD)",
            kind: "int",
            min: 0,
            step: 1,
            help: "B-602 fires when the day's total spend crosses this. 0 disables.",
          },
          {
            id: "Hard",
            label: "Hard deny at the proxy",
            kind: "bool",
            help: "In enforce mode, breach answers proxied requests with a synthetic 403 instead of just flagging. Default off.",
          },
        ],
      },
      {
        id: "alerts",
        label: "Alerts",
        path: ["Guard", "Alerts"],
        description: "Desktop notifications for record-worthy verdicts.",
        fields: [
          {
            id: "Desktop",
            label: "Desktop notifications",
            kind: "bool",
            help: "Exec-based notifications (notify-send / osascript / PowerShell). Default on.",
          },
          {
            id: "MinSeverity",
            label: "Min severity",
            kind: "select",
            options: ["info", "warn", "high", "critical"],
            help: "Alert threshold. Default high - warn gets noisy fast.",
          },
        ],
      },
      {
        id: "export",
        label: "Export",
        path: ["Guard", "Export"],
        description: "Verdict export into the OTel exporter stream.",
        fields: [
          {
            id: "OTel",
            label: "OTel export",
            kind: "bool",
            help: "Feed guard verdicts into [exporter.otel]. Both gates must be on. Default off.",
          },
        ],
      },
      {
        id: "dialects",
        label: "Native dialects",
        path: ["Guard", "Dialects"],
        description:
          "Compilation of the effective policy into AI-client-native permission config (claude-code permissions.deny/ask, …) at `observer init --guard`.",
        fields: [
          {
            id: "Compile",
            label: "Compile on init",
            kind: "bool",
            help: "Write compiled native rules during observer init. Drift later raises R-204; `observer guard compile --diff` shows it.",
          },
          {
            id: "Targets",
            label: "Targets",
            kind: "list",
            help: "Client names to compile for. Empty = all detected clients.",
          },
        ],
      },
      {
        id: "prompt",
        label: "Prompt-submit intervention",
        path: ["Guard", "Prompt"],
        description:
          "Warn/ask-once/block/redact when the developer's OWN prompt contains an API token or deterministic PII, before it reaches the model (R-172/R-190). Evaluated on the hook lane (native prompt-submit hooks, where wired) and/or the proxy lane (the latest user turn on an outbound request). Default on, ask-once. See the Security page's Prompt guard card for live status, events, and grants.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Master gate for the whole feature. Off = no detectors run over prompt text on either lane.",
          },
          {
            id: "Mode",
            label: "Global mode",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            help: "Default verdict for any detector with no override below. ask-once interrupts the FIRST occurrence of a finding set; an identical resend within the reconsider window goes through. This is a FLOOR — a stricter per-detector override below still wins.",
          },
          {
            id: "HookLane",
            label: "Hook lane",
            kind: "bool",
            help: "Evaluate prompt-submit hook channels (native \"block before the model sees it\" protocols, where the client supports one). Default on.",
          },
          {
            id: "ProxyLane",
            label: "Proxy lane",
            kind: "bool",
            help: "Evaluate the latest user turn on outbound proxy requests — the fallback for clients with no hook channel, or a second net on ones that have it. Only engages for traffic routed through the proxy. Default on.",
          },
          {
            id: "EnforceIndependent",
            label: "Independent of guard.mode",
            kind: "bool",
            help: "On (default): this feature acts on its own mode regardless of the top-level guard mode above, so ask-once/block work out of the box on a fresh install. Off: inherits the same observe/enforce gate every other guard channel uses (observe mode caps every outcome at warn).",
          },
          {
            id: "ReconsiderTTL",
            label: "Reconsider window",
            kind: "text",
            help: "Lifetime of an ask-once grant, e.g. \"30m\", \"1h\". An identical resend of the same finding set within this window is let through and recorded as confirmed.",
          },
          {
            id: "SuppressInCode",
            label: "Suppress in code context",
            kind: "bool",
            help: "Don't report a finding that appears inside a fenced code block or a variable-assignment-to-a-placeholder shape. Default on.",
          },
          {
            id: "MaxFindings",
            label: "Max findings per scan",
            kind: "int",
            min: 0,
            step: 1,
            help: "Defensive cap on findings recorded per prompt scan (a pathological input, not a normal-case ceiling).",
          },
          {
            id: "Allow",
            label: "Allow patterns",
            kind: "list",
            help: "RE2 regexes matched against a finding's MATCHED VALUE (never the whole prompt) — a match is dropped entirely. Test fixtures, known-fake keys.",
          },
        ],
      },
      {
        id: "prompt-detectors",
        label: "Prompt-submit detector overrides",
        path: ["Guard", "Prompt", "Detectors"],
        description:
          "Per-detector mode overrides for the most common secret + PII detectors — a stricter override here always wins over the global mode above; a looser one clamps up to it. The full detector vocabulary (GET /api/guard/prompt/detectors) is larger; less common ids stay config-file-only ([guard.prompt.detectors] in config.toml) to keep this list from growing unbounded.",
        fields: [
          {
            id: "credit_card",
            label: "Credit card",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "iban",
            label: "IBAN",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "us_ssn",
            label: "US SSN",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "uk_nino",
            label: "UK NINO",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "in_aadhaar",
            label: "India Aadhaar",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "in_pan",
            label: "India PAN",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "email",
            label: "Email address",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "phone_e164",
            label: "Phone (E.164)",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "phone_nanp",
            label: "Phone (NANP)",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
          {
            id: "github_pat",
            label: "GitHub token",
            kind: "select",
            options: ["off", "warn", "ask-once", "block", "redact"],
            showEffectiveMode: true,
          },
        ],
      },
    ],
  },
  routing: {
    id: "routing",
    // PUT /api/config/section/routing decodes ONLY the adoption-funnel
    // knobs below; every other [routing] sub-shape — tiers,
    // benchmark_files, path_classes, privacy rules, budget scopes,
    // reliability, key_pool (holds API keys), local_upstreams —
    // is deliberately ABSENT from this form (complex shapes + secrets
    // stay config-file-only) and the backend preserves the prior
    // values on every save. [[routing.rules]] is the one exception
    // (R2.2): the lint-gated fragment editor rendered BELOW the form
    // sends RulesTOML through this same seam; the form itself never
    // sends that key, so plain saves keep preserving rules wholesale.
    path: ["Routing"],
    description:
      "Model routing - opt-in, off by default. Pick a policy template and a mode: advise only logs what it would have done; enforce rewrites models (same provider shape, never silently). Everything binds at daemon start (restart banner after save). Promoting advise → enforce? Use the Routing page's Shadow card - it shows the readiness evidence first. Custom [[routing.rules]] are editable in the lint-gated editor below; tier overrides, budgets, privacy rules, key pools, and local upstreams stay config-file-only.",
    fields: [
      {
        id: "Enabled",
        label: "Enabled",
        kind: "bool",
        help: "Master gate. Off = no routing layer is constructed; decisions, savings, and shadow views stop accruing.",
      },
      {
        id: "Mode",
        label: "Mode",
        kind: "select",
        options: ["off", "advise", "enforce"],
        help: "advise (default) records what routing would have done - decision rows only, requests untouched. enforce actually rewrites the model on proxied requests (same provider shape). off keeps the layer constructed but inert.",
      },
      {
        id: "Policy",
        label: "Policy template",
        kind: "select",
        options: [
          "value",
          "frugal",
          "fast",
          "plan-exec",
          "strict-privacy",
          "enterprise-default",
          "custom",
        ],
        help: "value (default) = quality floors + cost minimization. frugal = budget-first. fast = latency-first. plan-exec = plan pinned flagship, execution downshifts. strict-privacy = local/allow-listed only. enterprise-default = value with conservative coherence. custom = your [[routing.rules]] only (config-file edit).",
      },
      {
        id: "DecisionLogRetentionDays",
        label: "Decision log retention (days)",
        kind: "int",
        min: 0,
        help: "Prune horizon for router_decisions rows (node-local, never pushed). Default 180. 0 disables pruning.",
      },
    ],
    groups: [
      {
        id: "stickiness",
        label: "Stickiness",
        path: ["Routing", "Stickiness"],
        description:
          "Session coherence - how reluctant routing is to switch models mid-session.",
        fields: [
          {
            id: "RespectCache",
            label: "Respect cache",
            kind: "bool",
            help: "Cache-priced switch economics: a switch whose prompt-cache forfeit costs more than it saves is held. Default on.",
          },
          {
            id: "MinTurnsBetweenSwitches",
            label: "Min turns between switches",
            kind: "int",
            min: 0,
            help: "Coherence floor - at least this many turns between model switches in one session. Default 5.",
          },
        ],
      },
      {
        id: "calibration",
        label: "Calibration",
        path: ["Routing", "Calibration"],
        description:
          "Outcome grading of routed turns. Display is always-on; acting on deltas needs the evidence gate below.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Run the calibration job over routed-turn outcomes. Default on (compute only - acting needs min samples).",
          },
          {
            id: "MinSamples",
            label: "Min samples",
            kind: "int",
            min: 0,
            help: "Evidence threshold below which a calibration delta never ACTS (it still displays). Default 50.",
          },
          {
            id: "AutoDemote",
            label: "Auto-demote",
            kind: "bool",
            help: "Demote a rule to advise when grading shows a regression. Default on. Demotions are in-memory and clear on restart.",
          },
        ],
      },
      {
        id: "rate_limit_window",
        label: "Rate-limit window",
        path: ["Routing", "RateLimitWindow"],
        description:
          "For subscription-window plans (Claude Pro/Max style): preserve flagship headroom for the turns that need it as the window fills.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Off by default - only acts for operators on subscription-window plans.",
          },
          {
            id: "HeadroomPct",
            label: "Headroom (%)",
            kind: "int",
            min: 0,
            max: 100,
            help: "Percent of the window's learned capacity preserved for hard turn-kinds. Default 15.",
          },
        ],
      },
    ],
  },
  mcp: {
    id: "mcp",
    // PUT /api/config/section/mcp decodes config.IntelligenceMCPConfig,
    // so the spec roots at ["Intelligence","MCP"] and group paths
    // include that prefix (the strip convention — see compression).
    path: ["Intelligence", "MCP"],
    description:
      "The on-demand MCP retrieval tools (get_file, get_symbols, get_relations, retrieve_stashed) and their audit log. Settings here bind when an AI client spawns its next observer MCP server - each session runs a fresh one, so saves apply to new sessions without a daemon restart. The 13 observability tools (get_cost_summary, search_past_outputs, …) are always on when MCP is registered and are not filtered here.",
    fields: [
      {
        id: "Features",
        label: "Tool allow-list",
        kind: "list",
        help: "Optional allow-list for the four retrieval tools (get_file, get_symbols, get_relations, retrieve_stashed). Empty = no filter, per-tool toggles below decide alone. A per-tool enabled=false always wins over this list.",
      },
    ],
    groups: [
      {
        id: "get_file",
        label: "get_file",
        path: ["Intelligence", "MCP", "GetFile"],
        description:
          "On-demand file retrieval. The extension allow-list and path deny-list here are SHARED by get_symbols and get_relations - one place to keep in sync.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Register the get_file tool on the next MCP server spawn.",
          },
          {
            id: "AllowExtensions",
            label: "Allow extensions",
            kind: "list",
            help: "File extensions the tool may read. Empty disables the allow-list entirely (binary-heavy workloads escape hatch).",
          },
          {
            id: "DenyPaths",
            label: "Deny paths",
            kind: "list",
            help: "Glob deny-list (supports *, ?, dir/**). Unsupported syntax ([abc], {a,b}) is inert and warned about at startup.",
          },
          {
            id: "MaxResponseKB",
            label: "Max response (KB)",
            kind: "int",
            min: 1,
            help: "Per-response byte cap. Truncated responses carry truncated:true so the agent retries tighter.",
          },
        ],
      },
      {
        id: "get_symbols",
        label: "get_symbols",
        path: ["Intelligence", "MCP", "GetSymbols"],
        description: "Symbol lookups over the code graph.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Register the get_symbols tool on the next MCP server spawn.",
          },
          {
            id: "MaxCallers",
            label: "Max callers",
            kind: "int",
            min: 1,
            help: "Cap on the callers list per symbol; callers_count still reports the unlimited total.",
          },
          {
            id: "MaxCallees",
            label: "Max callees",
            kind: "int",
            min: 1,
            help: "Cap on the callees list per symbol.",
          },
        ],
      },
      {
        id: "get_relations",
        label: "get_relations",
        path: ["Intelligence", "MCP", "GetRelations"],
        description: "Relation walks (BFS) over the code graph.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Register the get_relations tool on the next MCP server spawn.",
          },
          {
            id: "MaxDepth",
            label: "Max depth",
            kind: "int",
            min: 1,
            help: "BFS recursion cap. Lower on very large codebases.",
          },
          {
            id: "MaxResults",
            label: "Max results",
            kind: "int",
            min: 1,
            help: "Per-call reachable-node cap.",
          },
        ],
      },
      {
        id: "retrieve_stashed",
        label: "retrieve_stashed",
        path: ["Intelligence", "MCP", "RetrieveStashed"],
        description:
          "Retrieval surface for the proxy-side stash. Registered only when the stash itself is enabled AND this toggle is on - turning it off keeps stash compression active while denying the agent the read-back path.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Register retrieve_stashed (when the stash is enabled) on the next MCP server spawn.",
          },
          {
            id: "MaxShasPerCall",
            label: "Max SHAs per call",
            kind: "int",
            min: 1,
            help: "Cap on the array-form sha input per request. Default 25.",
          },
        ],
      },
      {
        id: "audit",
        label: "Audit log",
        path: ["Intelligence", "MCP", "Audit"],
        description:
          "One mcp_audit row per retrieval-tool call (success or denial). Local-only; feeds the value meter below and the advisor's schema-tax math. Turning it off makes MCP usage invisible to both.",
        fields: [
          {
            id: "Enabled",
            label: "Enabled",
            kind: "bool",
            help: "Write mcp_audit rows. Default on - local-only, small volume, high forensic value.",
          },
        ],
      },
    ],
  },
};
