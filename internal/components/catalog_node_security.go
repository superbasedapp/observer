package components

// catalog_node_security.go holds the security family of node rows: the
// security pillar's module root and its scanners, checks and feedback
// rows. nodeRows places this block after the terminals family.

// securityRows returns the security rows in catalog order.
func securityRows() []Component {
	return []Component{
		{
			// The security pillar's module root (security pillar plan
			// docs/plans/security-pillar-plan-2026-10-19.md section 4.2,
			// Phase A). Its children (security.trust, security.secrets,
			// security.deps, security.code and the drivers) are added by the
			// phases that build them, each with its own row.
			ID: "security", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Code security",
			About:  "Agent-aware code and supply-chain security on top of Guard: the findings store, the signed per-project posture the commit gate reads, the quick-scan channel and the Code security page. The core Guard rules R-112 to R-114 and R-165 are Guard's and stay active when this module is skipped.",
			Levels: lv(l1l2l3, l1l2l3, ""),
			Packages: []string{
				"internal/secfinding", "internal/secfinding/sarif", "internal/secscan", "internal/secsvc",
				"internal/secrules", "internal/secipc", "internal/secverify", "internal/secexcept", "internal/secmcp", "internal/secgithooks",
				"internal/secchange", "internal/seccifetch", "internal/secchangeexport",
				// The finding drawer's view-time dependency detail (pure; its
				// OSV record read is security.deps's osvdb, injected).
				"internal/secdepdetail",
				// The scanner drivers' shared pure cores (lane GATES-SEC): the
				// engine supply chain (pins, the offline signature pre-check,
				// the companion tree record) Opengrep, Trivy and KICS share,
				// and the IaC engines' core. Linked only by a compiled driver.
				"internal/secengine", "internal/seciac",
			},
			DirectModules: []string{"github.com/BurntSushi/toml"},
			Requires:      []string{"guard"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "<the org server named by --org-url>", Purpose: "CI verify fetch: the org's signed CI policy, the change records of a pull request's commits (commit shas and patch fingerprint hashes) and pinned drivers from the org's security mirror", Gate: "`observer security verify fetch` only, run by a CI job with a CI credential; no daemon path links it", Trigger: TriggerUserTriggered},
				},
				Listeners: []Listener{
					{Proto: "unix", Addr: "~/.observer/security/attach/attach.sock", Loopback: true, Auth: "owner-only (0700 dir, 0600 socket)", Trigger: TriggerAutomatic},
					{Proto: "pipe", Addr: `\\.\pipe\observer-attach-<hash of the security endpoint>`, Loopback: true, Auth: "owner-only ACL, deny network", Trigger: TriggerAutomatic},
				},
				FilesWritten: []string{"~/.observer/security/ (signed per-project posture files, dirty markers, seen marks)"},
			},
			Tables:       []string{"sec_findings", "sec_finding_events", "sec_scan_runs", "sec_baselines", "sec_finding_exceptions", "sec_finding_sightings", "sec_finding_commits"},
			Routes:       []string{"/api/security"},
			Verbs:        []string{"security"},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SHR-4", "SECP-1", "SECP-2", "SECP-3", "SECP-4", "SECP-11", "SECP-17", "SECP-23"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase B (lanes sec-b, sec-b2, sec-trustfix,
			// sec-trust2, sec-trust3): repository trust at the launch
			// chokepoint (the repo.trust row of launch_gates.go), rules
			// S-701 to S-705, the config baseline, the session-start flag and
			// `observer security trust`. On in the developer and full
			// distros and on an install with no [components] block: the
			// orchestrator offered it (plans decision log P-044) once the
			// blockers of P-022, P-029, P-031 and P-037 were closed.
			ID: "security.trust", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Repository trust",
			About:         "Checks the commands a repository makes an agent run (project hooks, MCP stdio servers, plugins, folder-open tasks) before an agent launches there, and records the developer's accept of each exact digest.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			Packages:      []string{"internal/sectrust", "internal/sectrustitem"},
			DirectModules: []string{"github.com/BurntSushi/toml", "github.com/tailscale/hujson", "gopkg.in/yaml.v3"},
			Requires:      []string{"security"},
			// [security.trust]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys:   []string{"security"},
			Tables:       []string{"sec_config_baseline", "sec_config_files"},
			Routes:       []string{"/api/security/trust"},
			Ledger:       []string{"SECP-5"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase D3 (lane sec-d3): user-configured scanner
			// drivers (driver kind custom, plan section 8.6). Off in every
			// distro; background only, never in a hook or the quick scan.
			// Runs go through the hardened runner (internal/extrun) and,
			// where the isolation component can hold them, its no-network
			// one-shot, which the cmd layer injects (never an import).
			ID: "security.scan.custom", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Custom scanners",
			About:    "Runs a scanner you configured through a structured, digest-pinned manifest (templates for gosec, Bandit and Semgrep) and reads only its SARIF. Findings are flag-only by default.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/seccustom", "internal/seccustomsvc"},
			Requires: []string{"security"},
			// [security.custom] (scheduled runs); config.ComponentSections
			// sets it aside while this component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Processes:    []string{"the executable a custom scanner manifest pins (gosec, bandit, semgrep from the built-in templates) and its declared companions (go, python3)", "bwrap (isolated runs, through the isolation component)"},
				FilesWritten: []string{"~/.observer/security/custom/ (accepted manifests and their audit log)", "<user cache>/superbased-observer/scanners/ (per-driver caches and per-run directories)"},
			},
			Routes:       []string{"/api/security/scanners/custom"},
			Ledger:       []string{"SECP-21"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase C (lanes sec-c and sec-c2): secret detection on
			// proposed writes (S-721), written files (the post-write seam),
			// staged and committed diffs (the commit quick scan and the
			// commit scan). A runtime child: its rules sit in the security
			// pack table (internal/secrules) and fire only while this id is
			// in the project's signed active pack set; its packages ship
			// with the module root until a phase splits them for L1.
			ID: "security.secrets", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Secret detection",
			About:      "Finds typed secrets in what an agent writes (before the write, in the hook), in written files, and in the diff a commit or push records, so the commit gate can stop an unscanned secret.",
			Levels:     lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires:   []string{"security"},
			ConfigKeys: []string{"security"},
			// The commit quick scan reads the diff through the core
			// read-only git envelope (internal/gitview); on a WSL daemon
			// reading a checkout on a Windows drive that git is the
			// Windows git.exe through WSL interop (R3-86, SECP-54).
			Surface:      Surface{Processes: []string{"git (read-only diff of what a commit or push records, through the read-only git envelope; for a checkout on a Windows drive read from WSL, the Windows git.exe through WSL interop)"}},
			Ledger:       []string{"SECP-18", "SECP-25", "SECP-54"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own yet: internal/secdetect, internal/secquickscan and internal/secpostwrite are compiled with the module root, so a build without the root drops them and this row is inactive (L2) otherwise.",
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase C: the native diff rules (CI workflow rules
			// S-771 to S-778, test tampering and the other diff observations
			// S-761 and S-767 to S-769), flag only. Runtime child like
			// security.secrets.
			ID: "security.code", Class: ClassFeature, Binary: BinaryNode,
			Title:        "Code rules",
			About:        "Native diff rules on agent changes and commits: dangerous GitHub Actions workflows and weakened tests. Flag only; no process, no egress.",
			Levels:       lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires:     []string{"security"},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-25"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own yet: internal/secciwf and internal/secdiffobs are compiled with the module root, so a build without the root drops them and this row is inactive (L2) otherwise.",
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase D1 (lanes sec-d1 and sec-d1fix): the install
			// gate and the online lane (security pillar plan sections 5.4,
			// 8.2, 8.3 and 8.5). On by default in the developer and full
			// distros (D-764 Q23), with the first-run disclosure accepted
			// before any online query; offered by lane sec-deps4 (decision
			// log P-036) after the operator's download rulings PT-19.
			ID: "security.deps", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Package checks",
			About:  "Checks packages an AI agent installs (and dependencies a manifest edit adds) against the signed malicious-packages list, popular names for typosquats, and, unless switched off, the OSV database and the public registry (including whether a version lost the build provenance earlier versions carried), before the install runs. Private package names never leave the machine. Also keeps each project's package inventory from its dependency scans, for a CycloneDX SBOM and a local licence check.",
			Levels: lv(l1l2l3, l1l2l3, ""),
			Packages: []string{
				"internal/secfeed", "internal/secfeed/online", "internal/secask",
				// OSV matching and the database store (Phase D2, section 8.2):
				// security.deps owns matching; its two driver children use them.
				"internal/secscan/depscan", "internal/secscan/depdriver", "internal/secscan/scalibrchild",
				"internal/secscan/osvdb", "internal/secscan/osvnet",
				// Project SBOM and licences (security coverage gaps plan items
				// 2 and 4): the inventory snapshot owner, the SBOM reader and
				// the local licence check.
				"internal/secinventory", "internal/secsbom", "internal/seclicense",
			},
			DirectModules: []string{"github.com/BurntSushi/toml", "golang.org/x/mod", "gopkg.in/yaml.v3"},
			Requires:      []string{"security"},
			ConfigKeys:    []string{"security"},
			Surface: Surface{
				Listeners: []Listener{
					{Proto: "unix", Addr: "~/.observer/security/ask/attach/attach.sock", Loopback: true, Auth: "owner-only (0700 dir, 0600 socket)", Trigger: TriggerAutomatic},
					{Proto: "pipe", Addr: `\\.\pipe\observer-attach-<hash of the ask endpoint>`, Loopback: true, Auth: "owner-only ACL, deny network", Trigger: TriggerAutomatic},
				},
				Egress: []Egress{
					{Host: "api.osv.dev", Purpose: "Online package check: ecosystem, public package name and version", Gate: "default on where the component is active, disclosed at first run, off per node; never on a managed node", Trigger: TriggerAutomatic},
					{Host: "<public package registries>", Purpose: "Online package check: whether a public package exists, when it was first published and, for npm and PyPI, which versions carry build provenance (PyPI: one more request to pypi.org/simple/<name>/)", Gate: "as api.osv.dev; provenance also needs [security.deps].provenance (default flag)", Trigger: TriggerAutomatic},
					{Host: "superbased.app", Purpose: "The signed malicious-packages and popular-names lists (signed content channel)", Gate: "where the component is active, with no consent (a plain download of public files, not a query about packages; operator ruling PT-19); [security.deps].index_download = false switches it off and the checks then use the index on disk; never on a managed node", Trigger: TriggerAutomatic},
				},
				FilesWritten: []string{"~/.observer/security/content/ (the signed index)", "~/.observer/security/pkgcache.json (online answers for the hook)", "~/.observer/security/deps-settings.json", "~/.observer/security/online-disclosure.json", "~/.observer/security/deps-index-verified.json (the index verified once per version)", "~/.observer/security/deps-notes/ (one marker per session that had the not-set-up note)", "~/.observer/security/deps-feed-etag.json (the feed envelopes' ETags)", "~/.observer/security/inventory/<project_root_hash>.json (each project's last dependency inventory: ecosystems, names, versions, dependency file paths; never file contents)"},
			},
			Tables:       []string{"sec_pkg_cache"},
			Routes:       []string{"/api/security/deps", "/api/security/sbom"},
			Ledger:       []string{"SECP-7", "SECP-22", "SECP-26", "SHR-7"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase C (lane sec-c3): opt-in local git hooks
			// (security pillar plan section 5.8, ruling Q12, ledger
			// SECP-14). Off in every distro: it writes into a repository,
			// so it runs only on the developer's per-repository consent.
			// Runtime child like security.secrets.
			ID: "security.githooks", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Local git hooks",
			About:    "On your consent per repository, a marked block in the pre-commit and pre-push hooks that checks a commit or push for secrets. Advisory for a human (--no-verify skips it), fail-open, removed byte-exactly.",
			Levels:   lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires: []string{"security"},
			Surface: Surface{
				FilesWritten: []string{"<repository>/.git/hooks/pre-commit and pre-push, or a core.hooksPath inside the repository (a marked block, per-repository consent)"},
			},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-14"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own beyond the pure internal/secgithooks, which is compiled with the module root, so a build without the root drops it and this row is inactive (L2) otherwise.",
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase H (lane sec-h): feedback to the agent after a
			// write (security pillar plan sections 5.11 (c), 6.1, 6.2 step 2
			// and 6.5 "Feedback to the agent after writes": Off, Q13). Off
			// in every distro and opt-in under a [components] block
			// (securityOptIn). Selected, it registers the post-tool events
			// no other binding registers (Gemini CLI AfterTool, Qwen Code
			// and Qoder PostToolUse, the plugin shim's tool.execute.after,
			// the Cline PostToolUse file hook) and puts up to three
			// templated lines into the host's post-tool reply. No process
			// and no egress of its own: the hook asks the daemon over the
			// module root's owner-only quick-scan endpoint. Runtime child
			// like security.secrets.
			ID: "security.feedback", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Feedback to the agent",
			About:      "After a write that produced a new high-confidence finding, the agent reads one templated line per finding in its own tool result, built from rule data only. Off unless you turn it on.",
			Levels:     lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires:   []string{"security"},
			Recommends: []string{"judge.client"},
			Surface: Surface{
				FilesWritten: []string{"the post-tool hook entries of Gemini CLI, Qwen Code and Qoder, the plugin shim's tool.execute.after handler, and ~/.cline/hooks/PostToolUse (only while selected, removed when deselected)"},
			},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-4", "SECP-15"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own yet: the pure internal/secfeedback, internal/secexplain and internal/secframework are compiled with the module root, so a build without the root drops them and this row is inactive (L2) otherwise.",
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase F2, node half (lane sec-f2a): the signed AI
			// change record per commit (security pillar plan sections 5.9
			// and 7.10, rulings Q8 and Q9). Off in every distro (Q9) and
			// opt-in under a [components] block (securityOptIn): with no
			// block no key is made, nothing is recorded, no change record
			// row is pushed and no repository is written. Selected, records
			// are kept and (managed, or an individual's own findings share)
			// shipped by default (Q8); git notes and the commit trailer
			// still need a person's per-repository consent. Runtime child
			// like security.githooks.
			ID: "security.provenance", Class: ClassFeature, Binary: BinaryNode,
			Title:    "AI change records",
			About:    "For each commit the attribution ties to agent activity, a signed record of the sessions, agents, models, line split, guard, scanner and finding summary (never prompt text), labelled node-reported attribution. Kept on this node and shipped to the org with the security rows; written into a repository as a git note or a commit trailer only on your per-repository consent.",
			Levels:   lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires: []string{"security"},
			Surface: Surface{
				Processes: []string{"git (read-only reads of a commit's tree and patch; `git notes` and the prepare-commit-msg hook only in a repository you consented for)"},
				FilesWritten: []string{
					"the OS keychain (service sbo-change-record-v1, the Ed25519 signing key), or a 0600 file beside the database where no keychain exists (reported as file_key)",
					"<repository>/.git refs/notes/observer and its prepare-commit-msg hook block (per-repository consent only)",
					"<repository>/.git refs/notes/ai (the experimental git-ai export, `observer security provenance export --notes`, under the same per-repository consent)",
				},
			},
			Tables:     []string{"sec_change_records", "sec_change_keys", "sec_change_consent"},
			ConfigKeys: []string{"security"},
			Ledger:     []string{"SECP-31", "SECP-32"},
			Teardown: []TeardownStep{{
				Owner: "observer security provenance consent --withdraw-all",
				What:  "Withdraws your consent in every repository and removes the prepare-commit-msg trailer block byte-exactly; git notes already written stay (a separate ref, delete them with git update-ref -d refs/notes/observer).",
			}},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own: the pure internal/secchange is compiled with the module root, so a build without the root drops it and this row is inactive (L2) otherwise.",
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase D2 (lane sec-d2): the linked OSV-SCALIBR
			// inventory driver (security pillar plan sections 4.2 and 8.4,
			// spike JSP-9b). The facade internal/secscan/scalibrfacade is the
			// only importer of SCALIBR and keeps a stub API under the omit
			// tag, so the row lists the module, not the package (the
			// ui.export-xlsx pattern). The scan runs in a child process of
			// the daemon through internal/extrun. dist(out, out, off, on)
			// (D-766: on in full, where it is compiled in), offered with
			// security.deps by lane sec-deps4 (decision log P-036); its
			// database waits for the developer's one-time accept (PT-19).
			ID: "security.scan.scalibr", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Dependency scan (OSV-SCALIBR)",
			About:         "Reads a project's lockfiles and manifests with the linked OSV-SCALIBR extractors, the actions its GitHub Actions workflows use, and its build artifacts (Go build info and cargo auditable data in the executables under bin/, dist/, target/release/ and any --artifacts directory; Java archives; Python wheel metadata), in a child process, and matches the packages against the local OSV database one ecosystem at a time. A missing database, a failed self-test or an unsupported platform shows as \"not scanned\", never clean. Beta on Windows and macOS.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			HostedIn:      []string{"internal/secscan/scalibrfacade"},
			DirectModules: []string{"github.com/google/osv-scalibr"},
			Requires:      []string{"security.deps"},
			Surface: Surface{
				Processes: []string{"observer (the scan child, `observer security scan-child`, through the shared runner)", "git (`git ls-files --stage`, read only, for the git submodule pins on an online scan: the Code security scan dialog's \"Also check online\" or `observer security scan --online`)"},
				Egress: []Egress{
					{Host: "superbased.app", Purpose: "superbased's signed mirror of the OSV database exports (security.osv_export: a base and a cumulative delta per ecosystem; no project data sent)", Gate: "after the developer's one-time accept (the Scanners card's confirm dialog, or `observer security scan db accept`; about 300 MB; never an agent, R-165), then automatic; individual node only, [security.deps] db_source auto (default) or feed; no request while the build carries no content-feed key", Trigger: TriggerAutomatic},
					{Host: "osv-vulnerabilities.storage.googleapis.com", Purpose: "The per-ecosystem OSV database exports, the fallback source (no project data sent)", Gate: "after the same accept; individual node only, when db_source = upstream, or db_source = auto with db_fallback_upstream on (default) and the signed mirror not published, not verifiable or unreachable (operator ruling PT-19, static feed mirroring plan section 7)", Trigger: TriggerAutomatic},
					{Host: "api.osv.dev", Purpose: "Online matching: ecosystem, public package name and version; and git submodules by the commit ids they are pinned to, only those ids (never a submodule's URL, path or name)", Gate: "an online scan only (the Code security scan dialog's \"Also check online\" or `observer security scan --online`), with security.deps online checks on and disclosed, individual node only", Trigger: TriggerOptIn},
					// Lane RM-2 (plan section 13): the SuperBased package lookup.
					{Host: "superbased.app", Purpose: "The superbased lookup's signed shard manifest and set descriptors (security.osv_shards; the same files for everyone, no project data sent)", Gate: "lookup mode remote or both ([security.deps] match) with the developer's own remote-lookup consent (the Privacy page's Package lookup card or `observer security lookup mode`; never an agent, R-165); individual node only; no request while the build carries no content-feed key", Trigger: TriggerOptIn},
					{Host: "shards.superbased.app", Purpose: "The superbased lookup's advisory shards: a short hash prefix per package name chooses which content-addressed shards are fetched; never a package name, version or code; private names withheld unless the developer separately chose to send them", Gate: "as the shard manifest: lookup mode remote or both with the remote-lookup consent, individual node only; only shards not already in the node-local cache", Trigger: TriggerOptIn},
				},
				FilesWritten: []string{
					"~/.observer/security/osv/ (the local OSV databases and their epochs)",
					"~/.observer/security/osv-db-consent.json (the developer's one-time accept of the database download: time, surface, account)",
					"~/.observer/security/osv-remote-consent.json and osv-remote-private-consent.json (the superbased lookup's consents: time, surface, account)",
					"~/.observer/security/osv-shards/ (the superbased lookup's verified shard cache, by digest, capped and evicted least recently used)",
					"<user cache>/superbased-observer/scanners/deps/remote/ (a remote lookup's assembled per-ecosystem export, removed after each match)",
					"~/.observer/security/deps-scan-last.json (each project's last scan per driver, by project hash)",
					"~/.observer/security/deps-scan.lock (one dependency scan at a time per machine)",
					"<user cache>/superbased-observer/scanners/deps/runs/ (the isolated scan child's run directory: links to the databases, removed after each run)",
				},
			},
			Ledger:       []string{"SECP-8", "SECP-19", "SECP-53"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, out, off, on),
		},
		{
			// OS and CI vulnerability scanning plan section 14.5 item 3b
			// (spike RG-0: GO reshaped, binary mode first): the Go
			// symbol-level reachability check. internal/secreachgovuln is the
			// only importer of golang.org/x/vuln (which brings x/tools and
			// x/telemetry, BSD-3-Clause with the Go PATENTS grant) and keeps a
			// stub API under the omit tag, so the row lists the module, not
			// the package (the security.scan.scalibr pattern); its pure core
			// internal/secreachgo and the tiers in internal/secreach are
			// core. The check runs in the dependency scan child under its
			// existing caps (binary mode, no toolchain, no network). Its
			// dotted parent security.reach does not exist; it requires
			// security.deps (the parent chain to security, as
			// security.scan.os does), not security.scan.scalibr: a
			// requirement stays active against a removal, so requiring
			// SCALIBR would keep that driver on for every config that removed
			// it. The check runs only inside the SCALIBR driver's child, so
			// with that driver off nothing runs. Section 14.13: out of minimal and developer,
			// off in managed, opt-in in full (dist(out, out, off, off) and
			// securityOptIn).
			ID: "security.reach.go", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Go function-level reachability (binary and source mode)",
			About:         "Checks each Go binary the dependency scan reads (under bin/, dist/, target/release/ and any --artifacts directory) with govulncheck's binary mode, linked in, against the advisories the scan matched, and labels each finding called or not called for that binary. Only advisories that list functions get a function-level label; a stripped binary is not checked (\"unknown: stripped binary\"). Binary mode runs in the scan child: no network, no Go toolchain. Source mode (`observer security scan --reach go-source`, or the Scanners card) runs osv-scanner's Go call analysis once per go.mod, which runs this machine's Go toolchain on the project: only when you start it, only for a project you opted in, in the isolation component's no-network run (refused without it unless you allow it), under a memory cap you set (default 12 GiB). Ranks and labels only; it never closes or hides a finding.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			HostedIn:      []string{"internal/secreachgovuln"},
			DirectModules: []string{"golang.org/x/vuln"},
			Requires:      []string{"security.deps"},
			Surface: Surface{
				Processes: []string{
					"observer (the scan child, `observer security scan-child`, through the shared runner; govulncheck runs in that process)",
					"osv-scanner (separately installed; source mode only, one process per go.mod with --call-analysis=go --offline -L <go.mod>, through the shared runner inside the isolation component's one-shot run)",
					"go, compile, asm, cgo, gcc and its children (the developer's own toolchain, started by osv-scanner's call analysis through `go list`; source mode only)",
				},
				FilesWritten: []string{
					"~/.observer/security/reach/<project hash>.json (each project's latest symbol check per binary and per go.mod: advisory ids, module versions, called or not called, the listed function a trace reached, the Go release a source-mode stdlib row assumed)",
					"~/.observer/security/reach-go-source-optin.json (the per-project source mode opt-in and its isolation override, signed under the posture key)",
					"<user cache>/superbased-observer/scanners/deps/runs/ (the matched records as a flat <id>.json directory for govulncheck; for source mode the linked Go export, Observer's empty osv-scanner config and the run's own HOME, GOCACHE, GOPATH, TMPDIR and telemetry directory; removed after each run)",
				},
			},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-51", "SECP-8"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, out, off, off),
		},
		{
			// OS and CI vulnerability scanning plan phase OS-2 route A
			// (sections 6.2, 6.3, 6.6.1 and 9.4): the OS package extractors
			// (os/dpkg, os/apk, os/rpm and osrelease, never artifact/image)
			// in the SCALIBR facade, and internal/secimage, the selective
			// layer reader of a `docker save` or OCI-layout tar. Distros like
			// security.scan.scalibr, whose facade and scan child it needs.
			// Manual only in this lane (`observer security scan image`): no
			// daemon loop.
			ID: "security.scan.os", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Image OS packages (OSV-SCALIBR)",
			About:         "Reads a container image's OS packages (Debian and Ubuntu dpkg, Alpine apk, Red Hat and Rocky rpm) from a `docker save` or OCI-layout tar or a root filesystem directory, without a daemon or a registry, and matches them in the scan child against the image's release database. A release with no database, no self-test or a failed self-test shows as \"not scanned\", never clean; kernel packages are left out and named. Red Hat family images are not scanned on Windows.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			Packages:      []string{"internal/secimage"},
			HostedIn:      []string{"internal/secscan/scalibrfacade"},
			DirectModules: []string{"github.com/klauspost/compress"},
			// Requires security.deps (the parent chain to security, as
			// security.scan.osv does), not security.scan.scalibr: a
			// requirement stays active against a removal, and this row is
			// new, so requiring SCALIBR would keep it on for every config
			// that removed it. The image verb instead refuses unless
			// security.scan.scalibr is selected too (requireImageScanSelected).
			Requires: []string{"security.deps"},
			Surface: Surface{
				Processes: []string{"observer (the scan child, `observer security scan-child`, through the shared runner)"},
				FilesWritten: []string{
					"~/.observer/security/image-scan-inventory.json (each scanned image's OS package inventory by image digest, for a rescan on a new database)",
					"<user cache>/superbased-observer/scanners/deps/runs/ (the image scan's run directory: the extracted allow-listed files and a link to the release database, removed after each run)",
				},
			},
			Ledger:       []string{"SECP-8", "SECP-19"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, out, off, on),
		},
		{
			// Security Phase D2 (lane sec-d2): the osv-scanner subprocess
			// driver, the configurable alternative to SCALIBR (Q17) and the
			// developer distro's default (D-766: dist(out, on, off, off)),
			// offered with security.deps by lane sec-deps4 (P-036). Never
			// bundled: used if installed, and with no osv-scanner it starts
			// no process and reports "not scanned".
			ID: "security.scan.osv", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Dependency scan (osv-scanner)",
			About:    "Runs a separately installed osv-scanner offline against the local OSV database. Not installed: no process starts, the project's dependencies show as \"not scanned\" and the vendor install is offered; nothing is installed without your consent.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/osvscanner"},
			Requires: []string{"security.deps"},
			Surface: Surface{
				Processes: []string{"osv-scanner (separately installed, run with --offline and --no-call-analysis=all)"},
				// Observer, not osv-scanner, downloads the database this
				// driver reads (the same store as security.scan.scalibr), so
				// the download is declared on every child that triggers it.
				Egress: []Egress{
					{Host: "superbased.app", Purpose: "superbased's signed mirror of the OSV database exports osv-scanner reads offline (no project data sent)", Gate: "as security.scan.scalibr: after the developer's one-time accept, then automatic; individual node only, db_source auto or feed", Trigger: TriggerAutomatic},
					{Host: "osv-vulnerabilities.storage.googleapis.com", Purpose: "The per-ecosystem OSV database exports, the fallback source (no project data sent)", Gate: "as security.scan.scalibr: after the same accept; individual node only, db_source upstream, or auto with the fallback on when the signed mirror cannot serve", Trigger: TriggerAutomatic},
				},
				FilesWritten: []string{
					"~/.observer/security/osv/ (the local OSV databases and their epochs)",
					"~/.observer/security/osv-db-consent.json (the developer's one-time accept of the database download: time, surface, account)",
					"~/.observer/security/osv-canary/ (the self-test project)",
					"~/.observer/security/osv-scanner-home/ (the engine's own HOME and cache)",
					"~/.observer/security/deps-scan-last.json (each project's last scan per driver, by project hash)",
					"~/.observer/security/deps-scan.lock (one dependency scan at a time per machine)",
				},
			},
			Ledger:       []string{"SECP-8"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, off),
		},
		{
			// Security Phase G lane G1 (sec-g1): the Opengrep process driver
			// and Observer's own observer-code rule pack (security pillar plan
			// sections 4.4, 5.5, 8.1 and 8.5; spike JSP-8). Off in every
			// distro (dist(out, off, off, off), section 4.2) and opt-in under a
			// [components] block (securityOptIn): it starts a third-party
			// process. Never bundled: used if installed, pinned and verified;
			// with no Opengrep it starts nothing. Findings are flag only (no
			// rule has a precision figure yet, PR7).
			ID: "security.scan.opengrep", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Code rules (Opengrep)",
			About:         "Runs Observer's own observer-code rules (Python, JavaScript and TypeScript, Go) with a pinned and verified Opengrep (installed by you, or by the guided install after a one-time size consent), full, diff-scoped, after agent writes, on each new commit or on a schedule. Not installed: no process starts. Findings are flag only.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			Packages:      []string{"internal/secrulepack", "internal/secscan/opengrep", "internal/secscan/opengrep/opengrepnet"},
			DirectModules: []string{"gopkg.in/yaml.v3"},
			Requires:      []string{"security.code"},
			// [security.scan.opengrep]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "github.com (release downloads, redirected only to release-assets.githubusercontent.com or objects.githubusercontent.com)", Purpose: "the guided install of the pinned Opengrep release, about 47 MB, checked against its sha256 pin", Gate: "consent", Trigger: TriggerUserTriggered},
					{Host: "superbased.app", Purpose: "the signed observer-code rule pack and engine pins (individual node; a managed node uses its org mirror)", Gate: "config: [security.scan.opengrep].feed, and only while an Opengrep engine is installed (P-061)", Trigger: TriggerOptIn},
				},
				Processes: []string{
					"opengrep (separately installed, pinned by sha256, with the files its self-extracting bundle unpacks into its own cache checked against the first verified run)",
					"git (Opengrep's own git ls-files and baseline, with the git hardening; and `git rev-parse` to resolve a --diff ref)",
					"bwrap (isolated runs, through the isolation component)",
				},
				FilesWritten: []string{
					"~/.observer/security/code-content/ (a signed rule pack or engine manifest an operator imported)",
					"~/.observer/security/opengrep-engine.json (the unpacked tree's digests and the last self-test)",
					"~/.observer/security/code-scan.lock (one Opengrep scan at a time per machine)",
					"~/.observer/security/opengrep-install-consent.json (the developer's size consent, signed), opengrep-install.json, code-content-fetch.json, opengrep-heads.json (the schedule's last run is read from the database, not a file)",
					"<user cache>/superbased-observer/scanners/opengrep/ (the guided install's bin/, the rule pack copy, the engine's own HOME and cache, per-run output directories)",
				},
			},
			Ledger:       []string{"SECP-27", "SECP-29"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase G lane G5 (sec-g5): the sarif-import driver
			// (security pillar plan sections 4.4 and 4.5.3 "In"). Reads ONE
			// SARIF file the developer names (a tool they ran themselves);
			// never runs a tool, never watches a folder. Off in every distro
			// and opt-in under a [components] block (securityOptIn). Findings
			// are flag only and carry an inferred lineage.
			ID: "security.scan.sarif-import", Class: ClassFeature, Binary: BinaryNode,
			Title:        "SARIF import",
			About:        "Imports one SARIF file that a scanner you ran yourself wrote (CodeQL, gosec, Bandit, Semgrep, the Claude or Codex Security plugin) as flag-only findings, each with an inferred lineage to the latest AI edit of its file. Observer never runs the tool; an import never shows a project clean.",
			Levels:       lv(l1l2l3, l1l2l3, ""),
			Packages:     []string{"internal/secscan/sarifimport"},
			Requires:     []string{"security.code"},
			Ledger:       []string{"SECP-33"},
			RestartClass: "hot",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase G lane G5 (sec-g5): the linked actionlint driver
			// (security pillar plan sections 4.4 "actionlint as a linked
			// driver", 5.6 and 8.7). MIT, in process behind a facade, its
			// shellcheck and pyflakes integrations off: it starts no process
			// and reads no repository actionlint config. Library-linked, so
			// compiled only in the managed and full distros
			// (dist(out, out, off, off), section 4.2) and opt-in under a
			// [components] block (securityOptIn). Findings are flag only.
			// No Verbs: Verbs are top-level verbs the gate owns, and `security`
			// belongs to security.code; the `security actionlint` subcommand
			// refuses on its own when the component is not selected (the
			// same holds for sarif-import's `security import-sarif`).
			// actionlint itself is the in-module copy
			// internal/thirdparty/actionlint (its UPSTREAM file records the
			// release and the patch), so its direct modules are the copy's.
			ID: "security.scan.actionlint", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Workflow lint (actionlint)",
			About:    "Lints a project's GitHub Actions workflows with actionlint, linked into Observer with its shellcheck and pyflakes integrations off, so no process starts. Findings are flag only.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/actionlint", "internal/thirdparty/actionlint"},
			DirectModules: []string{
				"github.com/bmatcuk/doublestar/v4", "github.com/fatih/color", "github.com/mattn/go-colorable",
				"github.com/mattn/go-runewidth", "github.com/mattn/go-shellwords", "github.com/robfig/cron/v3",
				"go.yaml.in/yaml/v4", "golang.org/x/sync", "golang.org/x/sys",
			},
			Requires:     []string{"security.code"},
			Ledger:       []string{"SECP-33"},
			RestartClass: "hot",
			Stability:    StabilityPreview,
			Distros:      dist(out, out, off, off),
		},
		{
			// Security lane GATES-SEC (operator ruling P-129, plan 5.6 P2, gap
			// G4): the Trivy process driver, misconfiguration only (`trivy
			// config` over Dockerfiles, Kubernetes, Terraform, CloudFormation
			// and Helm). Off in every distro (dist(out, off, off, off),
			// section 4.2) and opt-in under a [components] block
			// (securityOptIn): it starts a third-party process. Never bundled:
			// used if installed, or installed by the guided install after a
			// one-time size consent, pinned AND signature-checked (CVE-2026-
			// 33634). With no Trivy nothing starts and the project reads
			// not_scanned. Findings are flag only.
			ID: "security.scan.trivy", Class: ClassFeature, Binary: BinaryNode,
			Title:    "IaC checks (Trivy)",
			About:    "Checks a project's Dockerfiles, Kubernetes, Terraform, CloudFormation and Helm files with a pinned and signature-checked Trivy (installed by you, or by the guided install after a one-time size consent), on demand, on a schedule or after an agent writes such a file. Misconfiguration only, with every network path off. Not installed: no process starts. Findings are flag only.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/trivy", "internal/secscan/trivy/trivynet"},
			Requires: []string{"security.code"},
			// [security.scan.trivy]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "github.com (release downloads, redirected only to release-assets.githubusercontent.com or objects.githubusercontent.com)", Purpose: "the guided install of the pinned Trivy release archive and its sigstore bundle, checked against its sha256 pin and the pinned signing identity", Gate: "consent", Trigger: TriggerUserTriggered},
				},
				Processes: []string{
					"trivy (separately installed, pinned by sha256, `config` only, with --skip-check-update, --skip-version-check, --disable-telemetry and an in-memory cache)",
					"bwrap (isolated runs, through the isolation component)",
				},
				FilesWritten: []string{
					"~/.observer/security/iac-trivy.json (the engine's first-use digest, flag check and self-test), iac-trivy-install.json and iac-trivy-install-consent.json (signed)",
					"~/.observer/security/iac-scan.lock (one IaC scan at a time per machine)",
					"<user cache>/superbased-observer/scanners/trivy/ (the guided install's bin/, the engine's own HOME and cache, the canary project, per-run output directories)",
				},
			},
			Ledger:       []string{"SECP-34"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// OS and CI vulnerability scanning plan section 6.7 (operator
			// ruling Q6, lane OS-2 T): Trivy as the switchable alternative
			// driver for a container image's OS packages ([security.scan.image]
			// driver = "trivy"), beside the native route A (security.scan.os).
			// The same separately installed, pinned and signature-checked
			// Trivy binary as security.scan.trivy, run `image --input` or
			// `rootfs` with the vulnerability scanner over OS packages only,
			// offline and isolated; its database is Observer's download from
			// ghcr.io (the security.scan.trivy.db lane, internal/secscan/
			// trivydb) after a one-time accept. Off in every distro like the
			// Trivy row and opt-in (securityOptIn). Requires names security.deps
			// only (the parent chain to security): requiring security.scan.trivy
			// would bring that row back into a config that removed it
			// (TestIaCInertWithNoComponentsBlock). Like security.scan.os (lane N2) the image verb and
			// the trivy-db verbs refuse instead unless this row,
			// security.scan.trivy and security.deps are all selected.
			ID: "security.scan.image.trivy", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Image OS packages (Trivy)",
			About:    "Scans a container image's OS packages with a pinned and signature-checked Trivy, offline and isolated, against Trivy's own vulnerability database, which Observer downloads from ghcr.io after a one-time accept (about 140 MB, 1.7 GB on disk, checked every 6 hours). The alternative to the native OSV-SCALIBR image driver; choose it in the image engine picker on the Code security Scanners tab. A missing database, binary or isolation, or a failed self-test, shows as \"not scanned\", never clean.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/trivyimage", "internal/secscan/trivydb"},
			Requires: []string{"security.deps"},
			// [security.scan.image] is security.deps' section
			// (config.ComponentSections).
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "ghcr.io (redirected only to pkg-containers.githubusercontent.com for the layer)", Purpose: "Trivy's vulnerability database, the public OCI artifact ghcr.io/aquasecurity/trivy-db:2 (an anonymous pull token, the manifest by tag, the one database layer by digest, checked against the manifest's digest and size); nothing about a project or an image is sent", Gate: "after the developer's one-time accept (`observer security scan trivy-db accept` or the Scanners card's confirm dialog; never an agent, R-165), on an individual node only (a managed node's mirror does not serve it yet), on a Trivy image scan or `observer security scan trivy-db refresh`, at most every 6 hours and not before the database's own next update", Trigger: TriggerUserTriggered},
				},
				Processes: []string{
					"trivy (separately installed, the security.scan.trivy binary, pinned by sha256, `image --input` or `rootfs` with --scanners vuln --pkg-types os, --skip-db-update, --skip-java-db-update, --skip-vex-repo-update, --offline-scan, --skip-version-check, --disable-telemetry and an in-memory cache)",
					"bwrap (isolated runs, through the isolation component)",
				},
				FilesWritten: []string{
					"~/.observer/security/trivy-db-consent.json (the developer's one-time accept of the database download, signed)",
					"~/.observer/security/trivy-image.json (the binary digest whose --help listed every flag)",
					"<user cache>/superbased-observer/scanners/trivy-image/db/ (the unpacked database: one generation of trivy.db and metadata.json, and state.json)",
					"<user cache>/superbased-observer/scanners/trivy-image/runs/ (each run's cache, canary and report, removed after the run)",
				},
			},
			Ledger:       []string{"SECP-34", "SECP-8"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// OS and CI vulnerability scanning plan section 14.9 (item 7,
			// phase M3L-5; operator go 2026-11-04): the native passive DAST
			// checker. A few plain GETs to ONE dev server the developer names
			// on this machine, checked by the pure table internal/secdast; the
			// requests go only through internal/secdastnet (the security.dast
			// egress lane, kind local: loopback after resolution, no redirect
			// off the origin, bodies, requests and time capped). Its own signed
			// accept (internal/secdast/dastconsent); every run starts from the
			// developer (R-165 denies an agent the verb, the accept and the
			// record). Out of minimal, opt-in elsewhere (section 14.13: the
			// developer and full distros opt-in, managed off), so
			// dist(out, off, off, off) and securityOptIn. Requires names
			// security, its dotted parent. ZAP is a no-go and nuclei is not
			// driven (section 14.9). No route yet: the dashboard card is a
			// later step (R-165 reserves /api/security/dast).
			ID: "security.dast", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Local passive DAST",
			About:    "Checks a development server on this machine (localhost, 127.0.0.1 or ::1 with a port; nothing else is ever contacted) with a few plain GET requests: security headers, cookie flags, CORS, exposed .git and .env, directory listings, source maps, framework debug pages and version banners. Passive only: nothing is submitted or fuzzed. Runs only when you start it (command line or the Code security page), after a one-time accept; findings are flag only and stored against the project. Candidate servers come from the project's own files and, on Linux, the kernel's listen table; nothing is dialed to find them.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secdast", "internal/secdast/dastconsent", "internal/secdastnet"},
			Requires: []string{"security"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "<the loopback dev server the developer names (localhost, 127.0.0.0/8 or ::1, with a port)>", Purpose: "at most 16 plain GET requests per run (the page with a canary Origin, /.git/HEAD, /.env, one missing page, up to 3 same-origin scripts and their source maps); no cookie, credential or body is sent; refused for any address that is not loopback after resolution, and no redirect off the origin is followed", Gate: "`observer security dast <url>` or the Code security DAST card's Run, started by the developer (never an agent: R-165), after the one-time accept", Trigger: TriggerUserTriggered},
				},
				FilesWritten: []string{"~/.observer/security/dast-consent.json (the developer's one-time accept, signed)", "~/.observer/security/dast/<project_root_hash>.json (each origin's last run: the finding keys it reported, its time and outcome)"},
			},
			Routes:       []string{"/api/security/dast"},
			Ledger:       []string{"SHR-3"},
			RestartClass: "hot",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security lane GATES-SEC: the KICS process driver (plan 5.6 P2,
			// gap G4). Off in every distro and opt-in (securityOptIn). KICS
			// v2.2.0 publishes no release binaries and no signature, so there
			// is no guided install and no egress of its own: a KICS on this
			// machine is the developer's own, decided by its digest (labelled
			// on an individual node, refused on a managed node without an org
			// mirror pin). KICS asks api.github.com for its latest release on
			// every start with no flag to turn it off, so it runs only inside
			// the isolation component's no-network one-shot; elsewhere the
			// project reads not_scanned.
			ID: "security.scan.kics", Class: ClassFeature, Binary: BinaryNode,
			Title:    "IaC checks (KICS)",
			About:    "Checks a project's infrastructure-as-code files with KICS (installed by you; KICS publishes no release binaries), only inside the isolation component's no-network run, with its queries tree checked against the first verified run. Not installed or not isolated: no process starts. Findings are flag only.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/kics"},
			Requires: []string{"security.code"},
			// [security.scan.kics]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Processes: []string{
					"kics (separately installed, decided by its sha256, run only inside the isolation component's no-network one-shot, with its queries tree checked against the first verified run)",
					"bwrap (the isolated run, through the isolation component)",
				},
				FilesWritten: []string{
					"~/.observer/security/iac-kics.json (the engine's first-use digest, flag check, self-test and queries tree record)",
					"~/.observer/security/iac-scan.lock (one IaC scan at a time per machine)",
					"<user cache>/superbased-observer/scanners/kics/ (the engine's own HOME and cache, the canary project, per-run output directories)",
				},
			},
			Ledger:       []string{"SECP-34"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
	}
}
