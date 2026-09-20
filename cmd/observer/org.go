package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/intelligence/advisor"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgBundle is everything the org-* subcommands need from one config
// load + one DB open: the orgclient.Client (for enrolment / push), the
// underlying *store.Store (for direct cursor/state queries), and the
// resolved config so commands can render share-mode + scope. cleanup
// closes the DB; it is non-nil only when err is nil.
type orgBundle struct {
	client *orgclient.Client
	store  *store.Store
	// db is the SAME handle store wraps, kept for the CLI seams that take a
	// *sql.DB (the governance-grant resolver, the process cost engine).
	db      *sql.DB
	cfg     config.Config
	cleanup func()
}

// shareModeRule is one row of the share-mode line's table: the input that can
// lift this node above metadata-only, and how that line reads.
//
// It is a table because the answer had THREE inputs and the status line read
// exactly one of them (SF-12): a node running admin-managed, or holding the
// enterprise enrolment grant, was shipping raw command bodies and assistant
// prose while `observer org status` told its operator "metadata-only — the
// default". A status line that contradicts the wire is worse than no status
// line, and naming WHICH input lifted it is what lets an operator turn it back
// off.
type shareModeRule struct {
	// name is for the tests and for reading the table.
	name string
	// lifted reads the three inputs in the same order ShareOptions does.
	lifted func(fullContent, adminManaged, enterpriseGranted bool) bool
	// line is the whole rendered value.
	line string
}

// shareModeRules is ordered most-explicit-first: an operator who set
// full_content themselves is told that, even on a node that also holds the
// enterprise grant, because that is the switch they can turn off.
var shareModeRules = []shareModeRule{
	{
		name:   "full_content",
		lifted: func(full, _, _ bool) bool { return full },
		line: "FULL CONTENT (raw command bodies + assistant prose + raw paths SHIPPED) " +
			"— [org_client.share].full_content is true on this node",
	},
	{
		name:   "admin_managed",
		lifted: func(_, admin, _ bool) bool { return admin },
		line: "FULL CONTENT (raw command bodies + assistant prose + raw paths SHIPPED) " +
			"— [org_client.share].admin_managed is true; this node was provisioned as admin-managed",
	},
	{
		name:   "enterprise_grant",
		lifted: func(_, _, enterprise bool) bool { return enterprise },
		line: "FULL CONTENT (raw command bodies + assistant prose + raw paths SHIPPED) " +
			"— this node's managed enrolment grant carries the enterprise content authorities",
	},
	{
		// The total fallback, and the only line that may claim the default.
		name:   "metadata_only",
		lifted: func(bool, bool, bool) bool { return true },
		line:   "metadata-only (hashes; raws withheld) — the default",
	},
}

// shareModeLine renders the status line, walking the table top-down.
//
// The GATE is store.ShareOptions.ShipsRawContent — the one predicate the wire
// seam itself consults — so the line can never claim a posture the push does
// not have; the table only names which input produced it.
func shareModeLine(fullContent, adminManaged, enterpriseGranted bool) string {
	opts := store.ShareOptions{
		FullContent:       fullContent,
		AdminManaged:      adminManaged,
		EnterpriseGranted: enterpriseGranted,
	}
	if !opts.ShipsRawContent() {
		return shareModeRules[len(shareModeRules)-1].line
	}
	for _, rule := range shareModeRules {
		if rule.lifted(fullContent, adminManaged, enterpriseGranted) {
			return rule.line
		}
	}
	return shareModeRules[len(shareModeRules)-1].line
}

// enterpriseContentGranted resolves whether this node's managed enrolment
// grant carries the enterprise content authorities — the third, grant-borne
// input to ShipsRawContent, which no TOML key records.
//
// It mirrors budgetEnforcementGranted (costengine_wire.go) deliberately: both
// are "resolve the live governance grant from a short-lived CLI process", and
// both fail CLOSED on any error, because a status line must never claim a
// narrower posture than the push actually has.
func enterpriseContentGranted(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) bool {
	if st == nil {
		return false
	}
	if logger == nil {
		logger = slog.Default()
	}
	ngov := newNodeGovernanceHandle(governanceIdentityLoader(st), logger)
	loadNodeGovernanceLKG(ctx, cfg, st, ngov, logger)
	return ngov.Effective(ctx).GrantsEnterpriseContent()
}

// buildOrgClient assembles an orgclient.Client from config: the agent DB
// (store) plus the OS-keychain bearer store (0600-file fallback rooted next to
// the DB). It also reports whether the push loop is enabled in config (for
// status/enrol hints). The CLI uses a WARN-level logger so the client's own
// info logs do not compete with the command's printed output. The returned
// cleanup closes the DB; it is non-nil only when err is nil.
func buildOrgClient(ctx context.Context, configPath string) (c *orgclient.Client, cleanup func(), enabled bool, err error) {
	b, err := buildOrgBundle(ctx, configPath)
	if err != nil {
		return nil, nil, false, err
	}
	return b.client, b.cleanup, b.cfg.OrgClient.Enabled, nil
}

// buildOrgBundle is the richer variant new org subcommands use when they
// need the store handle (org status counts, org backfill, etc.) in
// addition to the client.
func buildOrgBundle(ctx context.Context, configPath string) (orgBundle, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return orgBundle{}, fmt.Errorf("load config: %w", err)
	}
	if cfg.OrgClient.KeychainID == "" {
		cfg.OrgClient.KeychainID = config.DefaultKeychainID
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
		return orgBundle{}, fmt.Errorf("ensure db dir: %w", err)
	}
	// No integrity probe here: `observer start` calls this synchronously (via
	// buildOrgClient) BEFORE the dashboard listener binds when [org_client]
	// is enabled — the same readiness-path position as buildOTelExporter,
	// so an un-skipped multi-GB `PRAGMA quick_check` here would block the
	// daemon for the full scan the moment a user enables org push. The org
	// CLI subcommands that also use this bundle are short-lived and never
	// need the probe either; the one authoritative quick_check runs off the
	// readiness path via db.RunStartupMaintenance.
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return orgBundle{}, fmt.Errorf("open db %s: %w", cfg.Observer.DBPath, err)
	}
	logger := newLogger("warn")
	st := store.New(database)
	// Wire the org-tier observability provider seam (obs-org-tier plan §2):
	// obs owns the obs_* reads; this binds them as plain func fields so the
	// push path can compose the opt-in tiers without internal/store importing
	// internal/obs. A no-op (zero providers) when obs is disabled / no_obs.
	st.SetObsOrgProviders(obsOrgProviders(ctx, cfg, database, logger))
	// Wire the advisor org-wire seam the same way (W3.2): advisor owns the
	// digest + advisor_state reads; store reaches them only through this
	// injected provider.
	st.SetAdvisorOrgProvider(func(ctx context.Context) ([]orgcontract.AdvisorSuggestionRow, error) {
		return advisor.OrgSuggestionRows(ctx, database)
	})
	// G1-COST(b): price $0-stored token_usage rows at push time from the
	// SAME cost.Engine the dashboard prices with, so the org rollup's SUM
	// of estimated_cost_usd stops under-reporting hook-only adapters.
	st.SetOrgPushPricer(orgPushPricer(acquireProcessCostEngine(ctx, cfg, database, logger)))
	bs := orgclient.OpenBearerStore(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath), logger)
	client := orgclient.New(cfg.OrgClient, st, bs, version, nil, logger)
	client.SetPolicyResourceCacheDir(policyResourceCacheDir(cfg))
	// Unenroll's step 2b (mini-spec §4.5) deletes the governance sidecar,
	// and `observer unenroll` runs through THIS bundle — not the daemon's
	// start.go wiring, which was the only place the path was set until the
	// 2026-08-15 live smoke caught the orphan: a CLI unenroll left the
	// sidecar behind, so hooks kept applying pins until its embedded grant
	// clock expired. Every org CLI client gets the path.
	client.SetGovernanceSidecarPath(config.ResolveGovernanceSidecarPath(cfg, ""))
	return orgBundle{
		client:  client,
		store:   st,
		db:      database,
		cfg:     cfg,
		cleanup: func() { _ = database.Close() },
	}, nil
}

// orgJudgeRelayFunc is the C1 judge relay seam
// (docs/plans/c1-judge-relay-spec-2026-08-15.md §3): a plain func value, NOT
// the orgclient.Client type, threaded from where the client is constructed
// (start.go / proxy.go, daemon scope) into the admission/eval judge build in
// obs_wire.go. This keeps the reverse-import boundary intact — obs_wire.go
// (and everything it calls in internal/obs) never imports internal/orgclient;
// only cmd/observer does. purpose is "admission" or "eval"; modelHint is
// optional and recorded only. A nil value means "no relay available" (not
// enrolled, or org push disabled) — callers must treat that as a soft-fail
// per §3, never a panic.
type orgJudgeRelayFunc func(ctx context.Context, purpose, prompt, modelHint string) (text, model string, err error)

// orgJudgeRelayFuncFor wraps an *orgclient.Client's JudgeRelay method as an
// orgJudgeRelayFunc. Nil-safe: a nil client (org push disabled, or client
// construction failed) yields a nil func, letting the caller detect
// "no relay available" without a type-asserting nil check of its own.
func orgJudgeRelayFuncFor(c *orgclient.Client) orgJudgeRelayFunc {
	if c == nil {
		return nil
	}
	return func(ctx context.Context, purpose, prompt, modelHint string) (string, string, error) {
		reply, err := c.JudgeRelay(ctx, purpose, prompt, modelHint)
		if err != nil {
			return "", "", err
		}
		return reply.Text, reply.Model, nil
	}
}

func newEnrollCmd() *cobra.Command {
	var (
		configPath       string
		linkURL          string
		idpURL           string
		writeBlock       bool
		wireClients      bool
		acceptGovernance bool
	)
	cmd := &cobra.Command{
		Use:   "enroll [<org-url> <token>]",
		Short: "Enrol this agent in an organisation's Observer server",
		Long: `Exchanges a one-time enrolment token for a long-lived bearer.

Four ways to supply credentials, in priority order:
  --idp <org-url>          Sign in with your organisation account instead of
                           being handed a code. Prints a short code and a URL;
                           approve in a browser on any device. Enrols this
                           machine as organisation-managed.
  --link <url>             A magic link the admin shared
                           (form: ` + "`http(s)://<host>/enrol/<code>`" + `)
  <org-url> <token>        Positional pair (legacy form)
  ENROLMENT_TOKEN env      With ` + "`--link <url-without-/enrol/code>`" + ` for org URL only

After enrolling, the agent (a) writes a default [org_client] block to
your config.toml (enabled=true, share.full_content=false,
push_interval_seconds=900) so you don't have to hand-edit TOML, and
(b) auto-wires the observer proxy + hooks + MCP into every detected
AI client (claude-code, codex, cursor, cline). Pass --no-write-block
or --wire-clients=false to opt out of either side. Only activity AFTER
enrolment is ever shared (the push cursor seeds at the current
high-water id).`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			orgURL, token, err := resolveEnrolCredentials(linkURL, idpURL, args)
			if err != nil {
				return err
			}
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			c, enabled := b.client, b.cfg.OrgClient.Enabled
			// ACP-P6c: --idp obtains the one-time enrolment code through an
			// IdP-verified browser approval instead of an admin handing one
			// over. Everything after this point is the SAME path the code
			// rail takes — the flow's whole design is that it produces an
			// ordinary enrolment code, not a second kind of enrolment.
			if idpURL != "" {
				flow := &idpEnrolFlow{client: c, out: cmd.OutOrStdout()}
				if token, err = flow.Run(cmd.Context(), orgURL); err != nil {
					return err
				}
			}
			enr, offer, err := c.Enroll(cmd.Context(), orgURL, token)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Enrolled in %s (org_id %s) as %s.\n", enr.OrgName, enr.OrgID, enr.UserEmail)
			fmt.Fprintf(out, "Pushing to %s.\n", enr.OrgServerURL)
			// Arc 4 P6a — managed enrolment binds this machine (plan §9). The
			// fingerprint is computed + sent ONLY for a managed node; an
			// individual/BYO node never emits a machine identity. Best-effort:
			// never fails the enrolment, just reports the outcome.
			if enr.IsManaged() {
				bindRes, bindErr := c.BindMachine(cmd.Context())
				printManagedBindOutcome(out, bindRes, bindErr)
			}
			// Admin-controlled Plane B (spec §2.3): the org may have offered
			// a GOVERNANCE GRANT alongside the enrolment. It is written only
			// after a human confirms it here — orgclient verified the
			// signature under the key this enrolment pinned, but consent is
			// a CLI concern, and a grant nobody agreed to would make the
			// whole consent model a lie.
			var gOut grantOutcome
			if offer != nil {
				gOut, err = confirmAndStoreGrant(cmd, b.store, offer, acceptGovernance)
				if err != nil {
					return err
				}
			}
			if enr.IsManaged() {
				printEnrolledNodeControl(cmd.Context(), out, b.store, b.cfg.Observer.DBPath)
			}
			if writeBlock {
				cfgPath, werr := resolveConfigPath(configPath)
				if werr != nil {
					fmt.Fprintf(out, "\nWarn: could not resolve config path to write [org_client] block: %v\n", werr)
				} else {
					if added, werr := ensureOrgClientBlock(cfgPath, enr.OrgServerURL); werr != nil {
						fmt.Fprintf(out, "\nWarn: could not write [org_client] block to %s: %v\n", cfgPath, werr)
					} else if added {
						fmt.Fprintf(out, "\nWrote default [org_client] block to %s — start `observer start` to begin pushing.\n", cfgPath)
						fmt.Fprintln(out, "  (A daemon already running with org push enabled picks up a re-enrolment within one push interval — no restart needed.)")
					} else if !enabled {
						fmt.Fprintln(out, "\nNote: [org_client] enabled = false — set it to true and restart `observer start` to begin pushing.")
					}
					// W-5 (operator ruling): managed sign-in IS the consent —
					// an accepted grant on a MANAGED enrolment auto-writes the
					// node-side [org_client.policy] keys the governed
					// families need, instead of leaving the developer to find
					// and hand-edit a fourth config key before extraction or
					// enforcement can flow at all. Never-server-forced still
					// holds: this is a node-side write the enrolment makes,
					// same idiom as the [org_client] block above, and the
					// node can edit or delete it at any time.
					//
					// managedPolicyFamiliesToWrite is the single owner of the
					// gate (declined / individual-tenancy / authority-that-
					// governs-nothing all resolve to nil, never a write) — a
					// real function under test, not logic re-derived in a
					// test file, so a future edit that loosens the gate here
					// fails a named test rather than silently starting to
					// write policy blocks for enrolments that never
					// consented to it.
					if families := managedPolicyFamiliesToWrite(gOut); len(families) > 0 {
						if added, werr := ensureManagedPolicyBlock(cfgPath, families); werr != nil {
							fmt.Fprintf(out, "\nWarn: could not write [org_client.policy] block to %s: %v\n", cfgPath, werr)
						} else if added {
							fmt.Fprintf(out, "\nWrote [org_client.policy] block to %s for the families this grant governs:\n", cfgPath)
							fmt.Fprintf(out, "  accept_families = %s\n", quotedTomlStringList(families))
							fmt.Fprintf(out, "  preauthorize_enforce = %s\n", quotedTomlStringList(families))
							fmt.Fprintln(out, "  Edit or remove this block at any time; only a future accepted grant writes it again.")
						}
					}
				}
			} else if !enabled {
				fmt.Fprintln(out, "\nNote: [org_client] enabled = false — set it to true and restart `observer start` to begin pushing.")
			}
			if wireClients {
				fmt.Fprintln(out, "\nAuto-wiring AI clients (hooks + MCP + proxy routing). Pass --wire-clients=false to skip.")
				// Resolve the proxy port from config so we can both
				// drive the registrar and probe whether the daemon
				// is currently listening.
				cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: configPath})
				proxyPort := 8820
				if cfgErr == nil && cfg.Proxy.Port > 0 {
					proxyPort = cfg.Proxy.Port
				}
				winHomes, winDistro, newReg := productionWindowsBrowserInputs()
				lines, claudeHint, codexHint, codexHooksHint, werr := wireAIClients(WireAIClientsOptions{
					ConfigPath:          configPath,
					ProxyPort:           proxyPort,
					All:                 true,
					WindowsBrowserHomes: winHomes,
					WSLDistro:           winDistro,
					NewWindowsRegistry:  newReg,
				})
				switch {
				case werr != nil:
					fmt.Fprintf(out, "Warn: auto-wire failed: %v\n", werr)
				case len(lines) == 0:
					fmt.Fprintln(out, "  (no AI clients detected — install Claude Code / Codex / Cursor / Cline first, then run `observer init`)")
				default:
					for _, ln := range lines {
						if ln != "" {
							fmt.Fprintln(out, "  "+ln)
						}
					}
					if claudeHint != "" {
						fmt.Fprintln(out)
						fmt.Fprint(out, claudeHint)
					}
					if codexHint != "" {
						fmt.Fprintln(out)
						fmt.Fprint(out, codexHint)
					}
					if codexHooksHint {
						fmt.Fprintln(out)
						fmt.Fprintln(out, "next: codex requires per-hook trust approval (security feature).")
						fmt.Fprintln(out, "  open codex once and run /hooks to mark all 6 entries trusted.")
					}
				}
				// Loud post-wire warning when the proxy isn't
				// listening: every Claude Code session on the host
				// now routes through 127.0.0.1:<port> after the
				// settings.json write, so a stopped proxy breaks
				// EVERY Claude Code instance until the operator
				// launches `observer start`. N4 caveat in
				// docs/audits/teams-test-regression-v1.8.2-2026-06-04.md.
				if !proxyReachable(fmt.Sprintf("http://127.0.0.1:%d", proxyPort), 200*time.Millisecond) {
					fmt.Fprintln(out)
					fmt.Fprintf(out, "WARNING: the observer proxy on 127.0.0.1:%d is not running.\n", proxyPort)
					fmt.Fprintln(out, "  Claude Code now routes through the proxy via ANTHROPIC_BASE_URL in")
					fmt.Fprintln(out, "  ~/.claude/settings.json, so every Claude Code session on this host")
					fmt.Fprintln(out, "  will fail with connection-refused until the proxy starts.")
					fmt.Fprintln(out, "  Run `observer start` in another shell (or `observer proxy start`).")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&linkURL, "link", "", "Enrol magic link (http(s)://host/enrol/<code>)")
	cmd.Flags().StringVar(&idpURL, "idp", "",
		"Enrol by signing in with your organisation account at this server (http(s)://host); prints a code to approve in a browser on any device")
	cmd.Flags().BoolVar(&writeBlock, "write-block", true, "auto-write a default [org_client] block to config.toml (use --write-block=false to skip)")
	cmd.Flags().BoolVar(&wireClients, "wire-clients", true, "auto-register hooks + MCP + proxy routing for every detected AI client (use --wire-clients=false to skip)")
	cmd.Flags().BoolVar(&acceptGovernance, "accept-governance", false,
		"accept an organisation governance grant without an interactive prompt (scripted rollout; see `observer org grant show` for what was granted)")
	return cmd
}

// errNotAnEnrolmentLink reports that a --link URL parsed as a dashboard
// sign-in surface (a set-password invite, or the login page) rather than a
// machine enrolment link. Both of those dashboard surfaces are ALSO of the
// form http(s)://host/<path>?token=<value> — a set-password invite is
// literally `?token=<id>.<secret>` (cmd/observer-org/users.go's
// set-password-link minter) — so without this classification
// resolveEnrolCredentials would happily hand the dashboard's invite/session
// token to POST /api/agent/enroll, which answers 401 with nothing to tell
// the developer that their *link*, not their credentials, was the wrong
// shape (grounded against internal/orgclient/client.go:498 Enroll).
type errNotAnEnrolmentLink struct {
	// path is the URL path that was actually seen (e.g. "/set-password"),
	// included so the message tells the developer exactly what it saw
	// rather than a generic "that's wrong" — see docs/demo-environment-playbook.md's
	// account terms for why a "sign-in invite" and an "enrolment link" are
	// two different objects a developer can otherwise confuse.
	path string
}

func (e *errNotAnEnrolmentLink) Error() string {
	return fmt.Sprintf(
		"observer enroll: %s is a dashboard sign-in invite, not a machine enrolment link. "+
			"Open it in a browser to set your password. To enrol this machine, ask your admin "+
			"for an enrolment link (observer enroll --link <url>) or run: observer enroll --idp <org-url>",
		e.path,
	)
}

// resolveEnrolCredentials resolves (orgURL, token) from one of:
//   - --idp http(s)://host                → (http(s)://host, "") — the code is
//     obtained later by idpEnrolFlow, so this form deliberately returns none
//   - --link http(s)://host/enrol/<code>  → (http(s)://host, <code>)
//   - positional [org-url, token]         → as supplied
//
// Returns a usage error when neither form provides both pieces, and an
// *errNotAnEnrolmentLink when --link resolves to a dashboard sign-in surface
// (/set-password or /login, or a bare ?token= on any other path) instead of
// the canonical /enrol/<code> form — those are dashboard credentials, not a
// machine enrolment token, and the two are easy to confuse because a
// set-password invite is also shaped like `?token=<value>`.
//
// The forms are MUTUALLY EXCLUSIVE and that is enforced rather than resolved
// by precedence: a developer who passes both a code and --idp has two
// different enrolments in mind, and silently picking one would enrol the
// machine under a tenancy they did not choose.
func resolveEnrolCredentials(linkURL, idpURL string, args []string) (string, string, error) {
	if idpURL != "" {
		if linkURL != "" || len(args) > 0 {
			return "", "", errors.New("observer enroll: --idp cannot be combined with --link or a positional enrolment code; pick one way to enrol")
		}
		u, err := url.Parse(idpURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", "", fmt.Errorf("invalid --idp URL %q (need http(s)://host)", idpURL)
		}
		return u.Scheme + "://" + u.Host, "", nil
	}
	if linkURL != "" {
		u, err := url.Parse(linkURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", "", fmt.Errorf("invalid --link URL %q (need http(s)://host/enrol/<code>)", linkURL)
		}
		path := strings.TrimPrefix(u.Path, "/")
		// /enrol/<code> is the ONLY canonical form. Classify everything
		// else by path BEFORE falling back to a bare ?token= query, so a
		// dashboard set-password invite or the login page — both of which
		// carry ?token=/session state that would otherwise parse as a
		// plausible-looking code — is refused with a message that says so,
		// instead of being POSTed to the enrol endpoint as a bad credential.
		if strings.HasPrefix(path, "enrol/") {
			code := strings.TrimPrefix(path, "enrol/")
			if code == "" {
				return "", "", fmt.Errorf("--link %q has no code (expected /enrol/<code> path or ?token=<code> query)", linkURL)
			}
			return u.Scheme + "://" + u.Host, code, nil
		}
		if path == "set-password" || path == "login" || u.Query().Get("token") != "" {
			return "", "", &errNotAnEnrolmentLink{path: "/" + path}
		}
		return "", "", fmt.Errorf("--link %q has no code (expected /enrol/<code> path or ?token=<code> query)", linkURL)
	}
	if len(args) == 2 {
		return args[0], args[1], nil
	}
	return "", "", errors.New("observer enroll: supply --link <url> OR positional <org-url> <token>")
}

// resolveConfigPath returns the effective config.toml path the operator's
// invocation will touch — explicit --config wins, otherwise
// $HOME/.observer/config.toml.
func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not resolve $HOME: %w", err)
	}
	return filepath.Join(home, ".observer", "config.toml"), nil
}

// ensureOrgClientBlock appends a default [org_client] block to the
// config file at path when one is not already present. Returns (added,
// err): added=true means we wrote a block; false + nil error means the
// block already existed and the file was untouched. Idempotent: a
// second call after the first is a no-op.
//
// orgServerURL is written into the block (tracker #41): the push loop
// reads the enrolment row's URL from the DB, but the policy-bundle
// runner and the disclosure surfaces read [org_client].org_server_url
// from config — leaving it unwritten left an enrolled node's guard
// org-layer silently unwired. Empty is tolerated (the key is simply
// omitted) so older callers keep working.
//
// The append is text-only — we never re-encode the whole file — so a
// hand-curated config keeps its comments, formatting, and ordering.
// hasOrgClientTableHeader reports whether body already declares a real
// [org_client] TOML table. It matches only a header at the start of a line
// (after indentation) — a bare substring search false-positived on configs
// whose COMMENTS mention [org_client], most notably the shipped gateway-role
// template (deploy/observer-gateway/config.toml), which made enroll silently
// skip the block write in exactly the deployment the template exists for
// (found live during the 2026-08-16 org-server-to-Azure move).
func hasOrgClientTableHeader(body string) bool {
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "[org_client]") {
			return true
		}
	}
	return false
}

func ensureOrgClientBlock(path, orgServerURL string) (bool, error) {
	body, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if hasOrgClientTableHeader(string(body)) {
		return false, nil
	}
	urlLine := ""
	if u := strings.TrimSpace(orgServerURL); u != "" {
		urlLine = "org_server_url = " + strconv.Quote(u) + "\n"
	}
	block := "\n[org_client]\n" +
		"# enabled = true means observer start ships activity rollups to the org server\n" +
		"# on every push_interval_seconds. Set to false to pause sharing without unenrolling.\n" +
		"enabled = true\n" +
		urlLine +
		"push_interval_seconds = 900\n" +
		"max_push_bytes = 1048576  # 1 MiB\n" +
		"# snapshot_interval_seconds bounds how often the SNAPSHOT wires (the\n" +
		"# aggregates and per-session/per-developer detail) recompute, even when\n" +
		"# their source data changed; the cursor wires (sessions/actions/turns)\n" +
		"# always ship every tick. Unset = 4x push_interval_seconds. Raise it to\n" +
		"# cut node CPU, set it negative to recompute on every tick.\n" +
		"# snapshot_interval_seconds = 480\n" +
		"\n" +
		"[org_client.share]\n" +
		"# full_content = true ships raw command bodies (run_command), assistant prose\n" +
		"# (task_complete), and raw filesystem paths to the org server. Default false\n" +
		"# ships only hashes — the metadata-only posture. The org admin cannot flip\n" +
		"# this remotely; it lives solely in this file. See docs/teams-getting-started.md.\n" +
		"full_content = false\n" +
		"# target_action_allowlist = [\"read_file\", \"edit_file\", \"write_file\"]\n" +
		"\n" +
		"[org_client.scope]\n" +
		"# project_root_allowlist = [\"/home/me/work/acme\"]\n" +
		"# project_root_denylist = [\"/home/me/personal\"]\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return false, err
	}
	return true, nil
}

// quotedTomlStringList renders items as a TOML inline array of quoted
// strings, e.g. ["admission.input", "node.governance"].
func quotedTomlStringList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// managedPolicyFamiliesToWrite is the W-5 gate: it decides whether an
// enrolment RunE should write an [org_client.policy] block at all, and for
// which families. It returns nil — never write — unless the grant was
// actually ACCEPTED (a declined or refused grant governs nothing), the
// enrolment is MANAGED tenancy (an individual/BYO node's managed sign-in
// was never the consent act; nothing here is auto-written for it), and the
// accepted authority governs at least one policy family
// (govern.GovernedFamilies already returns nil for an authority list that
// is empty, unrecognised, or only the retired capture.raise token).
//
// This is the single owner of that three-part condition — org.go's RunE
// calls it rather than re-deriving it inline, so the gate is one real
// function under test instead of logic that could silently drift between
// the call site and whatever a test asserts about it.
func managedPolicyFamiliesToWrite(g grantOutcome) []string {
	if !g.Accepted || !g.Managed {
		return nil
	}
	return govern.GovernedFamilies(g.Authority)
}

// ensureManagedPolicyBlock writes accept_families and preauthorize_enforce
// into [org_client.policy] when either is missing (W-5).
//
// Live finding, 2026-09-13: a managed devbox already carried a real
// [org_client.policy] table - written earlier by `observer config` for its
// node_workspace / node_environment / node_service keys - but never had
// these two keys. The old check treated "the table header exists" as "there
// is nothing to do here" and returned early, so `observer enroll
// --accept-governance` printed the write and then silently made it a
// no-op: the header's presence is not the presence of the keys it gates.
//
// The fix is a three-row decision table, walked top-down:
//
//  1. no [org_client.policy] table at all      -> append the whole default
//     block (unchanged from before this fix).
//  2. table exists, BOTH keys already present  -> no-op. A key is never
//     rewritten even if its value differs from families - the operator may
//     have deliberately narrowed it, and clobbering a hand-set value would
//     be exactly the kind of remote-feeling overwrite Never-server-forced
//     rules out for a node-side file.
//  3. table exists, one or both keys missing   -> insert only the missing
//     key line(s) right after the header line, before whatever the table
//     already held. Every other line in the file is preserved byte for
//     byte.
//
// Both keys, when written, are set to the SAME family list: the operator
// ruling for W-5 is that managed sign-in is the consent for exactly the
// families the accepted grant's authority governs, for both installing
// (accept_families) and live-enforcing (preauthorize_enforce) those
// families - a family the grant does not govern is never added to either
// list.
//
// Never-server-forced holds under every row: this is a node-side config
// write the enrolment makes, not a server override, and the node's own
// state - including a value it already set - always wins.
func ensureManagedPolicyBlock(path string, families []string) (bool, error) {
	if len(families) == 0 {
		return false, nil
	}
	body, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	list := quotedTomlStringList(families)
	lines := strings.Split(string(body), "\n")
	headerIdx := managedPolicyHeaderLineIndex(lines)

	var hasAccept, hasEnforce bool
	if headerIdx != -1 {
		section := lines[headerIdx+1 : tableSectionEnd(lines, headerIdx+1)]
		hasAccept = sectionDeclaresKey(section, "accept_families")
		hasEnforce = sectionDeclaresKey(section, "preauthorize_enforce")
	}

	switch {
	case headerIdx == -1:
		// Row 1.
		return true, appendManagedPolicyBlock(path, list)
	case hasAccept && hasEnforce:
		// Row 2.
		return false, nil
	default:
		// Row 3.
		return true, insertManagedPolicyKeys(path, lines, headerIdx, list, hasAccept, hasEnforce)
	}
}

// managedPolicyHeaderLineIndex returns the index into lines of the real
// [org_client.policy] table header, or -1 when none exists. Matching uses
// the same prefix-match idiom as hasOrgClientTableHeader (for [org_client]
// itself), for the same reason: a header is a line whose TRIMMED content
// starts with the literal table name, so indentation is tolerated but a
// comment mentioning the name is not.
func managedPolicyHeaderLineIndex(lines []string) int {
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "[org_client.policy]") {
			return i
		}
	}
	return -1
}

// tableSectionEnd returns the exclusive end, within lines, of the TOML
// table section that starts at index from: the index of the next line
// whose trimmed content opens a table header, or len(lines) when the
// section runs to end of file. A key inserted into this table must land
// before that boundary, or it silently re-homes into whichever table
// follows.
func tableSectionEnd(lines []string, from int) int {
	for i := from; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "[") {
			return i
		}
	}
	return len(lines)
}

// sectionDeclaresKey reports whether any non-comment, non-blank line in
// section assigns key - a bare "key = ..." or "key=..." line. A commented-
// out "# key = ..." line, or a different key that merely starts with the
// same characters (e.g. "accept_families_extra"), does not count.
func sectionDeclaresKey(section []string, key string) bool {
	for _, ln := range section {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rest := strings.TrimPrefix(trimmed, key)
		if rest == trimmed {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(rest, " \t"), "=") {
			return true
		}
	}
	return false
}

// appendManagedPolicyBlock is decision-table row 1: no [org_client.policy]
// table exists yet, so the whole default block is appended - append-only,
// comment-preserving, 0600, the same idiom as ensureOrgClientBlock.
func appendManagedPolicyBlock(path, list string) error {
	block := "\n[org_client.policy]\n" +
		"# Written automatically by `observer enroll` when this machine accepted a\n" +
		"# managed-organisation governance grant: managed sign-in is treated as the\n" +
		"# consent for the policy families that grant's authority governs, so you are\n" +
		"# not separately asked to hand-edit these keys. You may edit or remove this\n" +
		"# block at any time - the organisation cannot rewrite it remotely; only a\n" +
		"# future `observer enroll` in which you accept a grant writes it again.\n" +
		"# Removing it re-imposes manual consent: these families revert to \"reported\n" +
		"# but never durably installed\" until you (or a future accepted grant) add\n" +
		"# them back.\n" +
		"# See docs/teams-getting-started.md and `observer org grant show`.\n" +
		"accept_families = " + list + "\n" +
		"preauthorize_enforce = " + list + "\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(block)
	return err
}

// managedPolicyInsertionLines renders the lines to splice in for whichever
// of the two keys sectionDeclaresKey found missing - always at least one,
// since the caller only reaches here when hasAccept && hasEnforce is false.
func managedPolicyInsertionLines(list string, hasAccept, hasEnforce bool) []string {
	lines := []string{
		"# Added automatically by `observer enroll`: this machine accepted a",
		"# managed governance grant, and this table already existed for an",
		"# unrelated reason, so only the key(s) below were inserted rather than",
		"# the whole block being appended again. Edit or remove either key at",
		"# any time. See docs/teams-getting-started.md and `observer org grant show`.",
	}
	if !hasAccept {
		lines = append(lines, "accept_families = "+list)
	}
	if !hasEnforce {
		lines = append(lines, "preauthorize_enforce = "+list)
	}
	return lines
}

// insertManagedPolicyKeys is decision-table row 3: [org_client.policy]
// already exists but is missing one or both keys. It splices the missing
// key line(s) in immediately after the header line, before whatever the
// table already held, so the insertion always lands inside THIS table
// regardless of what follows in the file - and it writes atomically
// (temp file + rename in the same directory, 0600) rather than appending,
// since the new text lands in the middle of the file, not at the end.
func insertManagedPolicyKeys(path string, lines []string, headerIdx int, list string, hasAccept, hasEnforce bool) error {
	insertion := managedPolicyInsertionLines(list, hasAccept, hasEnforce)
	newLines := make([]string, 0, len(lines)+len(insertion))
	newLines = append(newLines, lines[:headerIdx+1]...)
	newLines = append(newLines, insertion...)
	newLines = append(newLines, lines[headerIdx+1:]...)
	return fsatomic.WriteFile(path, []byte(strings.Join(newLines, "\n")), fsatomic.Options{FilePerm: 0o600})
}

func newUnenrollCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "unenroll",
		Short: "Leave the enrolled organisation and clear local credentials",
		Long: `Deletes the local enrolment and removes the bearer + signing key from the
OS keychain. A running daemon's push loop stops within one interval. This does
not delete anything already shared with the org server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, cleanup, _, err := buildOrgClient(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st, err := c.Status(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !st.Enrolled {
				fmt.Fprintln(out, "Not enrolled; nothing to do.")
				return nil
			}
			if err := c.Unenroll(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintf(out, "Unenrolled from %s. Local credentials cleared.\n", st.OrgName)
			// Admin-controlled Plane B (spec §5.1): Unenroll deleted the
			// enrolment grant, so any organisation governance of this
			// machine's dashboard lifted with it. Say so explicitly — a
			// developer who ran this to get their pages back needs to know
			// it worked, and one who did not needs to know what changed.
			fmt.Fprintln(out, "Any organisation governance of this dashboard has been removed; local settings apply again.")
			fmt.Fprintln(out, "Data already shared with the organisation stays with the organisation.")

			// Symmetric cleanup for the RegisterClaudeCode write
			// from enroll: drop ANTHROPIC_BASE_URL from
			// ~/.claude/settings.json when it points at a loopback
			// (our own observer); preserve a deliberate third-party
			// proxy entry. Without this, every Claude Code session
			// keeps routing through the now-stopped observer proxy
			// after unenroll. Best-effort: a failure here doesn't
			// fail unenroll. N4 caveat in
			// docs/audits/teams-test-regression-v1.8.2-2026-06-04.md.
			cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: configPath})
			proxyPort := 8820
			if cfgErr == nil && cfg.Proxy.Port > 0 {
				proxyPort = cfg.Proxy.Port
			}
			if reg, regErr := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: proxyPort}); regErr == nil {
				if r := reg.UnregisterClaudeCode(); r.Error == nil && r.Added {
					fmt.Fprintf(out, "Removed ANTHROPIC_BASE_URL from %s.\n", r.ConfigPath)
				}
			}
			// Symmetric cleanup for the org policy bundle (guard spec
			// §14.2): leaving the org removes its strictness floor —
			// the guard's org layer loads from this cache, so it must
			// not outlive the enrolment. Best-effort (the file may
			// never have existed); the append-only key-pin history in
			// guard_policy_state deliberately stays as audit. A
			// running daemon's engines drop the layer at next start;
			// hook processes drop it on their next invocation.
			if cfgErr == nil {
				if cachePath := orgBundleCachePath(cfg); cachePath != "" {
					if rmErr := os.Remove(cachePath); rmErr == nil {
						fmt.Fprintf(out, "Removed org policy bundle %s.\n", cachePath)
					} else if !os.IsNotExist(rmErr) {
						fmt.Fprintf(out, "Warning: org policy bundle not removed (%v) — delete %s manually to drop the org policy layer.\n", rmErr, cachePath)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newOrgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "org",
		Short: "Organisation enrolment status, scope, manual push, preview, backfill",
	}
	cmd.AddCommand(
		newOrgStatusCmd(),
		newOrgPushStatusCmd(),
		newOrgPushNowCmd(),
		newOrgPreviewCmd(),
		newOrgBackfillCmd(),
		newOrgEmitManagedSettingsCmd(),
		newOrgGrantCmd(),
		newOrgRequestCmd(),
		newOrgRequestsCmd(),
	)
	return cmd
}

func newOrgStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show enrolment status, share mode, scope counts, and the last push",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			st, err := b.client.Status(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !st.Enrolled {
				fmt.Fprintln(out, "Not enrolled.")
				fmt.Fprintf(out, "Credential store: %s\n", st.Backend)
				return nil
			}
			fmt.Fprintf(out, "Enrolled:         yes\n")
			fmt.Fprintf(out, "Organisation:     %s (org_id %s)\n", st.OrgName, st.OrgID)
			fmt.Fprintf(out, "User:             %s\n", st.UserEmail)
			fmt.Fprintf(out, "Server:           %s\n", st.OrgServerURL)
			fmt.Fprintf(out, "Enrolled at:      %s\n", st.EnrolledAt)
			fmt.Fprintf(out, "Credential store: %s\n", st.Backend)
			fmt.Fprintf(out, "Pushing enabled:  %t\n", b.cfg.OrgClient.Enabled)
			fmt.Fprintln(out)

			// Share mode — the v1.8.0 per-node opt-in, read through the
			// SAME predicate the push seam uses (SF-12).
			fmt.Fprintf(out, "Share mode:       %s\n", shareModeLine(
				b.cfg.OrgClient.Share.FullContent,
				b.cfg.OrgClient.Share.AdminManaged,
				enterpriseContentGranted(cmd.Context(), b.cfg, b.store, newLogger("warn")),
			))
			if len(b.cfg.OrgClient.Share.TargetActionAllowlist) > 0 {
				fmt.Fprintf(out, "Per-action raws: %v\n", b.cfg.OrgClient.Share.TargetActionAllowlist)
			}
			fmt.Fprintln(out)

			// Scope counts: historical (already in the DB) vs.
			// eligible-since-enrolment (above the cursor, which the
			// agent seeds to the current high-water id at enrolment so
			// only post-enrolment activity is ever shareable).
			cur, err := b.store.LoadPushCursor(cmd.Context())
			if err != nil {
				return fmt.Errorf("load cursor: %w", err)
			}
			maxIDs, err := b.store.CurrentMaxIDs(cmd.Context())
			if err != nil {
				return fmt.Errorf("current max ids: %w", err)
			}
			fmt.Fprintf(out, "%-12s  %12s  %12s\n", "Table", "historical", "eligible")
			fmt.Fprintf(out, "%-12s  %12s  %12s\n", "----", "----------", "--------")
			fmt.Fprintf(out, "%-12s  %12d  %12d\n", "sessions", maxIDs.Sessions, maxIDs.Sessions-cur.Sessions)
			fmt.Fprintf(out, "%-12s  %12d  %12d\n", "actions", maxIDs.Actions, maxIDs.Actions-cur.Actions)
			fmt.Fprintf(out, "%-12s  %12d  %12d\n", "api_turns", maxIDs.APITurns, maxIDs.APITurns-cur.APITurns)
			fmt.Fprintf(out, "%-12s  %12d  %12d\n", "token_usage", maxIDs.TokenUsage, maxIDs.TokenUsage-cur.TokenUsage)
			fmt.Fprintf(out, "%-12s  %12d  %12d\n", "guard_events", maxIDs.GuardEvents, maxIDs.GuardEvents-cur.GuardEvents)
			fmt.Fprintln(out)

			// Explain an eligible==0 state in plain language (Phase C #8)
			// so "historical N, eligible 0" isn't a silent dead end.
			if reason := pushEligibilityReason(eligibleTotal(cur, maxIDs), historicalTotal(maxIDs), st.LastPush); reason != "" {
				fmt.Fprintln(out, "Why eligible = 0:")
				fmt.Fprintf(out, "  %s\n", reason)
				fmt.Fprintln(out)
			}

			if st.LastPush == nil {
				fmt.Fprintln(out, "Last push:        (none yet)")
			} else {
				lp := st.LastPush
				fmt.Fprintf(out, "Last push:        %s — %s, %d rows, %d bytes%s\n",
					lp.PushedAt, lp.Status, lp.RowCount, lp.Bytes, errSuffix(lp.Error))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// newOrgBackfillCmd lets the operator deliberately walk the push cursor
// backwards so historical rows become eligible. By default
// `observer enroll` seeds the cursor at the current high-water id, so
// only post-enrolment activity ships — protecting against the Issue 4
// "first push exfiltrates the whole local corpus" finding. backfill is
// the explicit opt-in to share older data.
func newOrgBackfillCmd() *cobra.Command {
	var (
		configPath string
		all        bool
		confirm    bool
	)
	cmd := &cobra.Command{
		Use:   "backfill",
		Short: "Rewind the push cursor so historical rows become eligible (opt-in)",
		Long: `Rewinds the push cursor so previously-skipped historical rows become
eligible for the next push loop. By default ` + "`observer enroll`" + ` seeds
the cursor at the current high-water id, so only post-enrolment activity is
ever shared. ` + "`backfill --all --confirm`" + ` resets every table cursor to
0 so the entire local corpus ships on the next push cycle.

Use ` + "`observer org status`" + ` first to see how many historical rows
would become eligible. Dry-run is the default; --confirm is required to
actually rewind.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !all {
				return errors.New("observer org backfill: --all is currently the only supported scope (pass --all --confirm to rewind every table cursor to 0)")
			}
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()

			cur, err := b.store.LoadPushCursor(cmd.Context())
			if err != nil {
				return fmt.Errorf("load cursor: %w", err)
			}
			maxIDs, err := b.store.CurrentMaxIDs(cmd.Context())
			if err != nil {
				return fmt.Errorf("current max ids: %w", err)
			}
			eligible := (maxIDs.Sessions - cur.Sessions) +
				(maxIDs.Actions - cur.Actions) +
				(maxIDs.APITurns - cur.APITurns) +
				(maxIDs.TokenUsage - cur.TokenUsage) +
				(maxIDs.GuardEvents - cur.GuardEvents)
			toUnlock := maxIDs.Sessions + maxIDs.Actions + maxIDs.APITurns + maxIDs.TokenUsage + maxIDs.GuardEvents

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "currently eligible: %d rows\n", eligible)
			fmt.Fprintf(out, "would unlock:       %d more rows (entire local corpus)\n", toUnlock-eligible)

			if !confirm {
				fmt.Fprintln(out, "\nDRY RUN — pass --confirm to rewind the cursor.")
				return nil
			}
			if err := b.store.SavePushCursor(cmd.Context(), store.PushCursor{}); err != nil {
				return fmt.Errorf("rewind cursor: %w", err)
			}
			fmt.Fprintln(out, "cursor reset to 0; next push cycle will ship the full corpus.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&all, "all", false, "rewind every table's cursor to 0 (currently the only supported scope)")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "actually rewind (omit for dry-run)")
	return cmd
}

// newOrgPreviewCmd surfaces the last-pushed wire bytes so the operator
// can see exactly what their enrolment is sending. Reads
// schema_meta.org_last_push_payload (written by orgclient on every
// successful push). The dashboard exposes the same data at
// /api/enrolment/last-payload; this CLI lets a node operator inspect
// it without a browser.
func newOrgPreviewCmd() *cobra.Command {
	var (
		configPath string
		raw        bool
	)
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Show the last successfully pushed wire payload (what you actually shared)",
		Long: `Prints the JSON of the most recent successfully pushed envelope — exactly
the rollup shape that left the machine, byte for byte (gzip is stripped
before storage). The dashboard surfaces this data at
/api/enrolment/last-payload; ` + "`observer org preview`" + ` provides the
same view without a browser.

The default output is pretty-printed JSON. --raw prints the stored bytes
unchanged for piping to jq.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			body, err := b.store.LoadLastPushPayload(cmd.Context())
			if err != nil {
				return fmt.Errorf("load last payload: %w", err)
			}
			if len(body) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no push has succeeded yet)")
				return nil
			}
			out := cmd.OutOrStdout()
			if raw {
				_, _ = out.Write(body)
				if len(body) > 0 && body[len(body)-1] != '\n' {
					fmt.Fprintln(out)
				}
				return nil
			}
			// Pretty-print: parse + re-marshal indented. Fall back to
			// raw if the stored bytes aren't valid JSON (e.g. a future
			// shape change). Always print a share-mode banner first so
			// the operator can interpret what they're seeing.
			shareLine := "metadata-only (hashes only; raw paths + content withheld)"
			if b.cfg.OrgClient.Share.FullContent {
				shareLine = "FULL CONTENT (raw paths + command bodies + assistant prose SHIPPED)"
			}
			fmt.Fprintf(out, "# Share mode at last push: %s\n", shareLine)
			var v any
			if err := json.Unmarshal(body, &v); err != nil {
				_, _ = out.Write(body)
				return nil
			}
			pretty, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				_, _ = out.Write(body)
				return nil
			}
			fmt.Fprintln(out, string(pretty))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&raw, "raw", false, "print the stored JSON bytes unchanged (for piping to jq)")
	return cmd
}

func newOrgPushNowCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "push-now",
		Short: "Push any unpushed activity to the enrolled organisation immediately",
		Long: `Runs one push cycle now instead of waiting for the interval. Useful to
verify enrolment end to end or to flush before shutting down.

The push carries this machine's CURRENT budget posture: the command fetches
the org budget policy first (the same verified, fail-open fetch the daemon
runs) and persists the verified document. While a daemon is running this is
a second writer of that cache, so a fenced daemon intervention (TERM/KILL
under an org cap) can be refused as "witness changed" until the daemon's own
next fetch (default 120 s) - a bounded window, documented in docs/budgets.md.

When nothing is queued the command reports the current cursor state
and the last push so the operator can tell why nothing happened —
"cursor up to date" vs "the auto-loop just pushed in the previous
interval".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			// The envelope carries the node's budget POSTURE, and this is a
			// separate process from the daemon: with nothing wired it would
			// ship no posture at all, and with the daemon's cold-cache shape
			// it would ship a primed `unreachable`. Wire the same boundary
			// the daemon runs, then push the way a loop cycle does - rails
			// first, envelope second (demo-estate finding 2026-09-20).
			wireCLIBudgetPosture(cmd.Context(), b, newLogger("warn"))
			res, err := b.client.PushNow(cmd.Context())
			if errors.Is(err, orgclient.ErrNotEnrolled) {
				return errors.New("not enrolled; run `observer enroll <org-url> <token>` first")
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if res.Empty {
				// M5.3: don't say "nothing to push" without the *why*.
				// Print the cursor + max IDs + last push so the operator
				// can tell whether the auto-loop just drained them or
				// whether the cursor is genuinely up to date with no
				// new activity.
				cur, cerr := b.store.LoadPushCursor(cmd.Context())
				maxIDs, mErr := b.store.CurrentMaxIDs(cmd.Context())
				lp, lpErr := b.store.LastPushLog(cmd.Context())
				fmt.Fprintln(out, "Nothing to push — the cursor is up to date.")
				if cerr == nil && mErr == nil {
					fmt.Fprintf(out, "  cursor:   sessions=%d actions=%d api_turns=%d token_usage=%d guard_events=%d\n",
						cur.Sessions, cur.Actions, cur.APITurns, cur.TokenUsage, cur.GuardEvents)
					fmt.Fprintf(out, "  max ids:  sessions=%d actions=%d api_turns=%d token_usage=%d guard_events=%d\n",
						maxIDs.Sessions, maxIDs.Actions, maxIDs.APITurns, maxIDs.TokenUsage, maxIDs.GuardEvents)
				}
				if lpErr == nil && lp != nil {
					fmt.Fprintf(out, "  last push: %s — %s, %d rows, %d bytes%s\n",
						lp.PushedAt, lp.Status, lp.RowCount, lp.Bytes, errSuffix(lp.Error))
				}
				return nil
			}
			fmt.Fprintf(out, "Pushed %d rows (%d bytes): accepted=%d deduped=%d\n",
				res.RowCount, res.Bytes, res.AcceptedRows, res.DedupedRows)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func errSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// printManagedBindOutcome reports the result of the Arc 4 P6a managed machine-
// binding step (plan §9) in one line. It never fails the enrolment: a binding
// problem is a note or warning, because the node is already enrolled and
// pushing. io.Writer is taken as the concrete cmd out to avoid importing io.
func printManagedBindOutcome(out interface{ Write([]byte) (int, error) }, res orgcontract.ManagedBindResponse, err error) {
	switch {
	case errors.Is(err, orgclient.ErrManagedBindRefused):
		fmt.Fprintln(out, "\nNotice: this machine is already bound to another managed node in your org. The bind was refused and your admin has been notified.")
	case err != nil:
		fmt.Fprintf(out, "\nWarn: managed machine-binding could not be recorded (enrolment is unaffected): %v\n", err)
	case res.Collision:
		fmt.Fprintln(out, "\nNotice: this machine is already bound to another managed node in your org. Your admin has been notified.")
	case res.Status == orgclient.ManagedBindUnbindable:
		fmt.Fprintln(out, "\nNote: this host has no stable machine identity, so the managed node shows as unbound to your admin.")
	case res.Status == orgclient.ManagedBindUnavailable:
		// Older server without the managed-bind route — nothing to report.
	default:
		fmt.Fprintf(out, "Bound this machine to your managed node (%s).\n", res.Status)
	}
}
