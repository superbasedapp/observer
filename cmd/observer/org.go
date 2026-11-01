package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
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
			"- [org_client.share].full_content is true on this node",
	},
	{
		name:   "admin_managed",
		lifted: func(_, admin, _ bool) bool { return admin },
		line: "FULL CONTENT (raw command bodies + assistant prose + raw paths SHIPPED) " +
			"- [org_client.share].admin_managed is true; this node was provisioned as admin-managed",
	},
	{
		name:   "enterprise_grant",
		lifted: func(_, _, enterprise bool) bool { return enterprise },
		line: "FULL CONTENT (raw command bodies + assistant prose + raw paths SHIPPED) " +
			"- this node's managed enrolment grant carries extract.managed, the organization-signed raise " +
			"to full content (see `observer org grant show`; your config file was not rewritten)",
	},
	{
		// The total fallback, and the only line that may claim the default.
		name:   "metadata_only",
		lifted: func(bool, bool, bool) bool { return true },
		line:   "metadata-only (hashes; raws withheld) - the default",
	},
}

// shareModeLine renders the status line, walking the table top-down.
//
// The GATE is store.ShareOptions.ShipsRawContent — the one predicate the wire
// seam itself consults — so the line can never claim a posture the push does
// not have; the table only names which input produced it.
func shareModeLine(fullContent, adminManaged, enterpriseGranted bool) string {
	return shareModeRuleFor(fullContent, adminManaged, enterpriseGranted).line
}

// shareModeRuleFor returns the shareModeRules row that names this posture.
// The dashboard reports the row's name as well as its line.
func shareModeRuleFor(fullContent, adminManaged, enterpriseGranted bool) shareModeRule {
	opts := store.ShareOptions{
		FullContent:       fullContent,
		AdminManaged:      adminManaged,
		EnterpriseGranted: enterpriseGranted,
	}
	if !opts.ShipsRawContent() {
		return shareModeRules[len(shareModeRules)-1]
	}
	for _, rule := range shareModeRules {
		if rule.lifted(fullContent, adminManaged, enterpriseGranted) {
			return rule
		}
	}
	return shareModeRules[len(shareModeRules)-1]
}

// enterpriseContentGranted resolves whether this node's managed enrolment
// grant is raising it to full content RIGHT NOW — the third, grant-borne
// input to ShipsRawContent, which no TOML key records. It reads
// govern.Effective.EnterpriseContentInForce, the same predicate the push seam
// ships under (governance_wire.lowerShareOptions), so the status line names
// exactly the posture the wire has: an org-signed extract.managed grant on a
// managed enrolment raises (Agent Access R9.5 / R11.10), an org body that
// lowered full_content makes it yield, a grant whose signature no longer
// verifies (govern.StateGrantSignatureInvalid), or one whose key pin or
// enrolment generation no longer matches, grants nothing.
//
// It mirrors budgetEnforcementGranted (costengine_wire.go) deliberately: both
// are "resolve the live governance grant from a short-lived CLI process", and
// both fail CLOSED on any error, because a status line must never claim a
// narrower posture than the push actually has.
func enterpriseContentGranted(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) bool {
	return enterpriseContentEffective(ctx, cfg, st, logger).EnterpriseContentInForce()
}

// enterpriseContentEffective resolves the live governance posture the way
// the daemon does (identity loader + last-known-good body), for the CLI
// surfaces that report what the grant does to content sharing. A nil store
// resolves to the zero posture, which grants nothing.
func enterpriseContentEffective(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) govern.Effective {
	if st == nil {
		return govern.Effective{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	ngov := newNodeGovernanceHandle(governanceIdentityLoader(st), logger)
	loadNodeGovernanceLKG(ctx, cfg, st, ngov, logger)
	return ngov.Effective(ctx)
}

// enterpriseContentRule is one row of the `observer org grant show`
// "Content sharing" line: the resolved posture it matches and the line it
// renders. Walked top-down; the last row is the total fallback.
type enterpriseContentRule struct {
	name  string
	match func(eff govern.Effective) bool
	line  string
}

// enterpriseContentRules names WHY the grant does or does not raise this
// machine to full content, most-specific first. The order matters: a grant
// that carries the umbrella but is lowered by the org must say "lowered", not
// "raised", and an individual enrolment must be told the token is inert for
// it rather than being shown a raise it will never get.
var enterpriseContentRules = []enterpriseContentRule{
	{
		name:  "raised",
		match: func(e govern.Effective) bool { return e.EnterpriseContentInForce() },
		line: "Content:      FULL (L2) - this organization-signed grant carries extract.managed on a managed enrolment,\n" +
			"              so raw command bodies, assistant prose and raw paths ship. Your config file was\n" +
			"              not rewritten; the raise lives in this grant and lapses with it.",
	},
	{
		name:  "lowered",
		match: func(e govern.Effective) bool { return e.GrantsEnterpriseContent() && !e.EnterpriseContentInForce() },
		line: "Content:      LOWERED - the grant carries extract.managed, but your organization's signed policy\n" +
			"              sets share.full_content = false for this machine, so only hashes ship under it.",
	},
	{
		name: "inert_individual",
		// Effective.Authority is the grant's KNOWN token list as recorded
		// (govern normalize/splitAuthority), so it still names the umbrella
		// on an individual enrolment even though HonoredAuthority applies
		// nothing under it — which is exactly the fact this row explains.
		match: func(e govern.Effective) bool {
			return !e.Managed && containsString(govern.AuthorityExtractManaged, e.Authority)
		},
		line: "Content:      unchanged - extract.managed is on this grant but this is an INDIVIDUAL enrolment,\n" +
			"              where that token is inert; only your own [org_client.share].full_content decides.",
	},
	{
		name:  "not_granted",
		match: func(govern.Effective) bool { return true },
		line: "Content:      unchanged by this grant - it carries no extract.managed; what ships is decided by\n" +
			"              your own [org_client.share] block (see `observer org status`).",
	},
}

// enterpriseContentLine renders the `observer org grant show` line that says
// what the recorded grant does to this machine's content sharing, resolved
// through the same predicate the push seam ships under.
func enterpriseContentLine(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) string {
	return enterpriseContentLineFor(enterpriseContentEffective(ctx, cfg, st, logger))
}

// enterpriseContentLineFor walks enterpriseContentRules for a resolved
// posture. Split from enterpriseContentLine so the table is testable without
// a store.
func enterpriseContentLineFor(eff govern.Effective) string {
	for _, rule := range enterpriseContentRules {
		if rule.match(eff) {
			return rule.line
		}
	}
	return enterpriseContentRules[len(enterpriseContentRules)-1].line
}

// governancePostureLine returns a one-line WARNING for `observer org status`
// when this node's governance posture is one of the loud states, and ""
// otherwise.
//
// It resolves through the SAME loader + resolver the daemon uses
// (governanceIdentityLoader -> govern.Resolve), so status can never disagree
// with what the node actually applies. It fails SILENT on a read error: a
// status command must not invent a tamper claim out of a transient SQLite
// error.
func governancePostureLine(ctx context.Context, st *store.Store) string {
	if st == nil {
		return ""
	}
	grant, live, err := governanceIdentityLoader(st)(ctx)
	if err != nil || grant == nil {
		return ""
	}
	switch govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC()).State {
	case govern.StateGrantSignatureInvalid:
		return "Governance:       ALTERED - the organization grant stored on this machine does not verify." +
			"\n                  Organization governance is NOT being applied. Run `observer org grant show`."
	case govern.StateKeyPinMismatch:
		return "Governance:       KEY MISMATCH - the grant is bound to a signing key this machine no longer pins." +
			"\n                  Organization governance is NOT being applied. Run `observer org grant show`."
	case govern.StateIdentityChanged:
		return "Governance:       STALE - the grant belongs to an enrolment this machine no longer holds." +
			"\n                  Organization governance is NOT being applied. Re-enrol to re-establish it."
	case govern.StateGrantExpired:
		return "Governance:       EXPIRED - the organization grant has lapsed; local settings apply again."
	default:
		return ""
	}
}

// buildOrgClient assembles an orgclient.Client from config: the agent DB
// (store) plus the OS-keychain bearer store (0600-file fallback rooted next to
// the DB). It also reports whether the push loop is enabled in config (for
// status/enrol hints). The CLI uses a WARN-level logger so the client's own
// info logs do not compete with the command's printed output. The returned
// cleanup closes the DB; it is non-nil only when err is nil.
func buildOrgClient(ctx context.Context, configPath string) (c *orgclient.Client, cleanup func(), enabled bool, err error) {
	b, err := buildOrgBundleWith(ctx, configPath, true)
	if err != nil {
		return nil, nil, false, err
	}
	return b.client, b.cleanup, b.cfg.OrgClient.Enabled, nil
}

// buildOrgBundle is the richer variant new org subcommands use when they
// need the store handle (org status counts, org backfill, etc.) in
// addition to the client.
func buildOrgBundle(ctx context.Context, configPath string) (orgBundle, error) {
	return buildOrgBundleWith(ctx, configPath, false)
}

// buildOrgBundleWith is buildOrgBundle; quietWhenNotEnrolled opens the bearer
// store without the keychain-downgrade warning when [org_client] is not
// enabled (T-735). buildOrgClient passes true: `observer proxy start` builds
// it on every node, enrolled or not, and a never-enrolled node was warned
// about a keychain it does not use. The enrol and org verbs keep the warning.
func buildOrgBundleWith(ctx context.Context, configPath string, quietWhenNotEnrolled bool) (orgBundle, error) {
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
	// Agent Access P11 (c): the shadow-MCP discovery inventory seam over the
	// node's client MCP configs (mcpinventory_wire.go). Composes nothing
	// unless the share posture attaches the wire (orgpush.go).
	st.SetMCPInventoryProviders(mcpInventoryProviders())
	var bs orgclient.BearerStore
	if quietWhenNotEnrolled && !cfg.OrgClient.Enabled {
		bs = orgclient.OpenBearerStoreQuiet(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath))
	} else {
		bs = orgclient.OpenBearerStore(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath), logger)
	}
	client := orgclient.New(cfg.OrgClient, st, bs, version, nil, logger)
	client.SetPolicyResourceCacheDir(policyResourceCacheDir(cfg))
	// T-656: the machine key that proves this machine on the grant and budget
	// rails, kept beside the enrolment secret.
	client.SetMachineKeyStore(orgclient.OpenMachineKeyStore(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath)))
	// WINNODE2 (16c): the routine machine-key warning prints once per
	// install and reason, not on every CLI call.
	client.SetNoticeDir(filepath.Dir(cfg.Observer.DBPath))
	// Unenroll's step 2b (mini-spec §4.5) deletes the governance sidecar,
	// and `observer unenroll` runs through THIS bundle — not the daemon's
	// start.go wiring, which was the only place the path was set until the
	// 2026-08-15 live smoke caught the orphan: a CLI unenroll left the
	// sidecar behind, so hooks kept applying pins until its embedded grant
	// clock expired. Every org CLI client gets the path.
	client.SetGovernanceSidecarPath(config.ResolveGovernanceSidecarPath(cfg, ""))
	// The node.features sidecar is identity-bound the same way: without the
	// path a CLI re-enrolment or unenroll kept the previous org's
	// tools.disallow list in force (T-393, Integration 7 live smoke).
	client.SetFeaturesSidecarPath(config.ResolveFeaturesSidecarPath(cfg, ""))
	// T-393: a re-enrolment into another org, or as another member, removes
	// the previous identity's org guard bundle file.
	client.SetGuardBundleCachePath(orgBundleCachePath(cfg))
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
		acceptIntel      bool
	)
	cmd := &cobra.Command{
		Use:   "enroll [<org-url> <token>]",
		Short: "Enrol this agent in an organization's Observer server",
		Long: `Exchanges a one-time enrolment token for a long-lived bearer.

Four ways to supply credentials, in priority order:
  --idp <org-url>          Sign in with your organization account instead of
                           being handed a code. Prints a short code and a URL;
                           approve in a browser on any device. Enrols this
                           machine as organization-managed.
  --link <url>             A magic link the admin shared
                           (form: ` + "`http(s)://<host>/enrol/<code>`" + `)
  <org-url> <token>        Positional pair (legacy form)
  ENROLMENT_TOKEN env      With ` + "`--link <url-without-/enrol/code>`" + ` for org URL only

After enrolling, the agent (a) writes a default [org_client] block to
your config.toml (enabled=true, the default 120 s push ceiling, and
share.full_content=true for an organization-managed enrolment - the
teams/enterprise capture posture ships raw content - or false for an
individual one, which keeps the node-side opt-in) so you don't have to
hand-edit TOML, and
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
			// T-642: the one enrolment sequence Settings > Enrolment also
			// runs (exchange, managed bind, default [org_client] block).
			seq, err := runEnrolSequence(cmd.Context(), b, configPath, orgURL, token, writeBlock)
			if err != nil {
				return err
			}
			enr, offer := seq.enr, seq.offer
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Enrolled in %s (org_id %s) as %s.\n", enr.OrgName, enr.OrgID, enr.UserEmail)
			fmt.Fprintf(out, "Pushing to %s.\n", enr.OrgServerURL)
			if seq.bindTried {
				printManagedBindOutcome(out, seq.bindRes, seq.bindErr)
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
				cfgPath, werr := seq.cfgPath, seq.cfgPathErr
				if werr != nil {
					fmt.Fprintf(out, "\nWarn: could not resolve config path to write [org_client] block: %v\n", werr)
				} else {
					printEnrolBlockOutcome(out, seq, cfgPath, enabled)
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
					if families, added, werr := writeAcceptedGrantPolicy(seq.blockConfigPath(), gOut); len(families) > 0 {
						if werr != nil {
							fmt.Fprintf(out, "\nWarn: could not write [org_client.policy] block to %s: %v\n", cfgPath, werr)
						} else if added {
							fmt.Fprintf(out, "\nWrote [org_client.policy] block to %s for the families this grant governs:\n", cfgPath)
							for _, kl := range managedPolicyKeyLines(families) {
								fmt.Fprintf(out, "  %s = %s\n", kl.key, kl.list)
							}
							fmt.Fprintln(out, "  Edit or remove this block at any time; only a future accepted grant writes it again.")
						}
					}
				}
			} else if !enabled {
				fmt.Fprintln(out, "\nNote: [org_client] enabled = false - set it to true and restart `observer start` to begin pushing.")
			}
			// Cloud Intelligence parity (design 3.7 step 2): when the org
			// makes the individual-tenancy opt-in a condition of membership,
			// show its terms now and ask. Declining leaves the machine
			// enrolled with the requirement PENDING (Accept or Leave later).
			offerOrgIntelAtEnrol(cmd, b, configPath, acceptIntel)
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
				// T-642: register against the running daemon's binary, not
				// whichever binary ran this enrol (enrolWireRules).
				wireBin := enrolWireBinaryFor(out, b.cfg.Observer.DBPath)
				winHomes, winDistro, newReg := productionWindowsBrowserInputs()
				var report WireReport
				lines, claudeHint, codexHint, codexHooksHint, werr := wireAIClients(WireAIClientsOptions{
					Report:              &report,
					RouteWriter:         routeprov.WriterEnrolment,
					ConfigPath:          configPath,
					BinaryPath:          wireBin,
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
					fmt.Fprintln(out, "  (no AI clients detected - install Claude Code / Codex / Cursor / Cline first, then run `observer init`)")
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
						fmt.Fprintln(out, "note: codex runs a hook only once it is trusted (security feature).")
						fmt.Fprintln(out, codexTrustLine())
					}
				}
				// Loud post-wire warning when the proxy isn't
				// listening: every Claude Code session on the host
				// now routes through 127.0.0.1:<port> after the
				// settings.json write, so a stopped proxy breaks
				// EVERY Claude Code instance until the operator
				// launches `observer start`. N4 caveat in
				// docs/audits/teams-test-regression-v1.8.2-2026-06-04.md.
				// Only for routes that are actually in place (T-736): a node
				// with no Claude Code got this warning for a write that never
				// happened.
				if len(report.RoutesInPlace) > 0 && !proxyReachable(fmt.Sprintf("http://127.0.0.1:%d", proxyPort), 200*time.Millisecond) {
					printProxyDownWarning(out, proxyPort, report.RoutesInPlace)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&linkURL, "link", "", "Enrol magic link (http(s)://host/enrol/<code>)")
	cmd.Flags().StringVar(&idpURL, "idp", "",
		"Enrol by signing in with your organization account at this server (http(s)://host); prints a code to approve in a browser on any device")
	cmd.Flags().BoolVar(&writeBlock, "write-block", true, "auto-write a default [org_client] block to config.toml (use --write-block=false to skip)")
	cmd.Flags().BoolVar(&wireClients, "wire-clients", true, "auto-register hooks + MCP + proxy routing for every detected AI client (use --wire-clients=false to skip)")
	cmd.Flags().BoolVar(&acceptGovernance, "accept-governance", false,
		"accept an organization governance grant without an interactive prompt (scripted rollout; see `observer org grant show` for what was granted)")
	cmd.Flags().BoolVar(&acceptIntel, "accept-intel-consent", false,
		"accept the organization's Cloud Intelligence terms without an interactive prompt when it requires them (the terms are still printed; see `observer intel status`)")
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

// enrolShareDefault is one row of the enrolment-time share-default table:
// which enrolment TENANCY it covers, the full_content value `observer org
// enroll` writes into the node's own [org_client.share] block for it, the
// comment that block carries so the operator reading the file later knows
// why, and the one-line summary the enrol command prints.
//
// It is a table (CLAUDE.md #5) because the answer has exactly two rows and
// they are the product's whole capture-posture split (Agent Access R9.5,
// robustness finding PR-014): a MANAGED enrolment — the teams/enterprise
// posture, the server's own verdict on the enrol response
// (orgcontract.EnrollResponse.Tenancy, stored as store.Enrolment.Tenancy) —
// captures everything, so a managed node shipping hashes only is a defect;
// an INDIVIDUAL enrolment keeps the node-side opt-in the privacy plane is
// built on. Both rows are NODE-authored config written by the enrolment the
// developer just ran, never a remote force: the org admin has no toggle for
// this file, and a node enrolled before the managed row existed is raised by
// the org-SIGNED extract.managed grant it is shown (govern.Effective.
// EnterpriseContentInForce), not by a rewrite of this block.
type enrolShareDefault struct {
	// name is for the tests and for reading the table.
	name string
	// managed is the tenancy the row covers (store.Enrolment.IsManaged).
	managed bool
	// fullContent is the [org_client.share].full_content value written.
	fullContent bool
	// comment is the TOML comment block written above the key, each line
	// already prefixed with "# " and newline-terminated.
	comment string
	// summary is the one-line explanation the enrol command prints.
	summary string
}

// enrolShareDefaults is the whole table; enrolShareDefaultFor walks it.
var enrolShareDefaults = []enrolShareDefault{
	{
		name:        "managed",
		managed:     true,
		fullContent: true,
		comment: "# full_content = true: this machine enrolled as ORGANISATION-MANAGED (the\n" +
			"# teams/enterprise capture posture), so raw command bodies (run_command),\n" +
			"# assistant prose (task_complete), and raw filesystem paths ship to the org\n" +
			"# server. `observer enroll` wrote this from the enrolment's tenancy: it is\n" +
			"# a node-authored value in this file, not a remote toggle. A managed node that\n" +
			"# ships hashes only is a defect, so lower this only on an explicit admin\n" +
			"# decision (the org can also lower it through its signed governance policy).\n" +
			"# See docs/teams-getting-started.md.\n",
		summary: "organization-managed enrolment (teams/enterprise) ships full content; a node-authored value you can read in the file",
	},
	{
		name:        "individual",
		managed:     false,
		fullContent: false,
		comment: "# full_content = true ships raw command bodies (run_command), assistant prose\n" +
			"# (task_complete), and raw filesystem paths to the org server. Default false\n" +
			"# ships only hashes - the metadata-only posture. The org admin cannot flip\n" +
			"# this remotely; it lives solely in this file. See docs/teams-getting-started.md.\n",
		summary: "individual enrolment keeps the node-side opt-in (hashes only until you set it to true)",
	},
}

// enrolShareDefaultFor returns the enrolShareDefaults row for the enrolment
// tenancy. The table is closed (two rows, one per tenancy class), so the
// walk always matches; the individual row is the fallback so an unexpected
// caller can never be defaulted INTO full content.
func enrolShareDefaultFor(managed bool) enrolShareDefault {
	for _, row := range enrolShareDefaults {
		if row.managed == managed {
			return row
		}
	}
	return enrolShareDefaults[len(enrolShareDefaults)-1]
}

// ensureOrgClientBlock appends the default [org_client] block to the config
// file at path unless one is already present, and reports whether it wrote.
// managed selects the enrolShareDefaults row (the share.full_content value
// and its comment); the rest of the block is tenancy-independent. It never
// modifies an existing block, which is what keeps the already-enrolled case
// on the signed-grant rail rather than a silent config rewrite.
func ensureOrgClientBlock(path, orgServerURL string, managed bool) (bool, error) {
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
	share := enrolShareDefaultFor(managed)
	// The documented default is rendered from the one constant the push loop
	// falls back to (T-403), so the comment cannot drift from the behaviour.
	defaultPush := strconv.Itoa(config.DefaultPushIntervalSeconds)
	block := "\n[org_client]\n" +
		"# enabled = true means observer start ships activity rollups to the org server\n" +
		"# on every push_interval_seconds. Set to false to pause sharing without unenrolling.\n" +
		"enabled = true\n" +
		urlLine +
		"# push_interval_seconds is the CEILING between pushes (default " + defaultPush + "). New\n" +
		"# activity pushes sooner (15 s floor), and a managed organization can lower\n" +
		"# it through signed node governance (org_client.push_interval_seconds).\n" +
		"# Left unset on purpose: unset follows the release default, a written\n" +
		"# value would pin this machine to it across upgrades.\n" +
		"# push_interval_seconds = " + defaultPush + "\n" +
		"max_push_bytes = 1048576  # 1 MiB\n" +
		"# snapshot_interval_seconds bounds how often the SNAPSHOT wires (the\n" +
		"# aggregates and per-session/per-developer detail) recompute, even when\n" +
		"# their source data changed; the cursor wires (sessions/actions/turns)\n" +
		"# always ship every tick. Unset = 4x push_interval_seconds. Raise it to\n" +
		"# cut node CPU, set it negative to recompute on every tick.\n" +
		"# snapshot_interval_seconds = 480\n" +
		"\n" +
		"[org_client.share]\n" +
		share.comment +
		"full_content = " + strconv.FormatBool(share.fullContent) + "\n" +
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
func quotedTomlStringList(items []string) string { return orgenrol.TOMLStringList(items) }

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
	// ManagedGovernedFamilies, not GovernedFamilies: a managed grant that
	// governs anything also governs node.features (review C156-04), so feature
	// locks, tools.disallow and the G8 tool and feature grants take effect on
	// a managed node without a hand edit. Only families linked in this build
	// are written (linkedManagedFamilies, audit SHR-KIT finding 1).
	return linkedManagedFamilies(govern.ManagedGovernedFamilies(g.Authority))
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
	lines := strings.Split(string(body), "\n")
	headerIdx := managedPolicyHeaderLineIndex(lines)
	if headerIdx == -1 {
		// Row 1.
		return true, appendManagedPolicyBlock(path, families)
	}
	section := lines[headerIdx+1 : tableSectionEnd(lines, headerIdx+1)]
	var missing []string
	for _, kl := range managedPolicyKeyLines(families) {
		if !sectionDeclaresKey(section, kl.key) {
			missing = append(missing, kl.key+" = "+kl.list)
		}
	}
	if len(missing) == 0 {
		// Row 2.
		return false, nil
	}
	// Row 3.
	return true, insertManagedPolicyKeys(path, lines, headerIdx, missing)
}

// managedPolicyKeyLinesText renders managedPolicyKeyLines on one line.
func managedPolicyKeyLinesText(families []string) string {
	var parts []string
	for _, kl := range managedPolicyKeyLines(families) {
		parts = append(parts, kl.key+" = "+kl.list)
	}
	return strings.Join(parts, ", ")
}

// managedPolicyKeyLine is one key the managed write sets and its value.
type managedPolicyKeyLine struct{ key, list string }

// managedPolicyKeyLines splits families over the keys (plans decision
// P-047, config.SplitPolicyFamilies): a family every released binary knows
// goes to accept_families / preauthorize_enforce, every other one (a module
// floor family) to accept_module_families / preauthorize_module_enforce,
// which an older binary ignores instead of refusing the file. A pair with
// no family is not written.
func managedPolicyKeyLines(families []string) []managedPolicyKeyLine {
	released, module := config.SplitPolicyFamilies(families)
	var out []managedPolicyKeyLine
	if len(released) > 0 {
		l := quotedTomlStringList(released)
		out = append(out, managedPolicyKeyLine{"accept_families", l}, managedPolicyKeyLine{"preauthorize_enforce", l})
	}
	if len(module) > 0 {
		l := quotedTomlStringList(module)
		out = append(out, managedPolicyKeyLine{"accept_module_families", l}, managedPolicyKeyLine{"preauthorize_module_enforce", l})
	}
	return out
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
func appendManagedPolicyBlock(path string, families []string) error {
	var keys strings.Builder
	for _, kl := range managedPolicyKeyLines(families) {
		keys.WriteString(kl.key + " = " + kl.list + "\n")
	}
	block := "\n[org_client.policy]\n" +
		"# Written automatically by `observer enroll` when this machine accepted a\n" +
		"# managed-organization governance grant: managed sign-in is treated as the\n" +
		"# consent for the policy families that grant's authority governs, so you are\n" +
		"# not separately asked to hand-edit these keys. You may edit or remove this\n" +
		"# block at any time - the organization cannot rewrite it remotely; only a\n" +
		"# future `observer enroll` in which you accept a grant writes it again, and\n" +
		"# `observer start` adds a family your grant governs only the first time\n" +
		"# this enrolment is offered it (never one it was offered before).\n" +
		"# Removing it re-imposes manual consent: these families revert to \"reported\n" +
		"# but never durably installed\" until you (or a future accepted grant) add\n" +
		"# them back.\n" +
		"# See docs/teams-getting-started.md and `observer org grant show`.\n" +
		keys.String()
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

// managedPolicyInsertionLines renders the lines to splice in for the keys
// sectionDeclaresKey found missing - always at least one.
func managedPolicyInsertionLines(missing []string) []string {
	lines := []string{
		"# Added automatically by `observer enroll`: this machine accepted a",
		"# managed governance grant, and this table already existed for an",
		"# unrelated reason, so only the key(s) below were inserted rather than",
		"# the whole block being appended again. Edit or remove either key at",
		"# any time. See docs/teams-getting-started.md and `observer org grant show`.",
	}
	return append(lines, missing...)
}

// insertManagedPolicyKeys is decision-table row 3: [org_client.policy]
// already exists but is missing one or both keys. It splices the missing
// key line(s) in immediately after the header line, before whatever the
// table already held, so the insertion always lands inside THIS table
// regardless of what follows in the file - and it writes atomically
// (temp file + rename in the same directory, 0600) rather than appending,
// since the new text lands in the middle of the file, not at the end.
func insertManagedPolicyKeys(path string, lines []string, headerIdx int, missing []string) error {
	insertion := managedPolicyInsertionLines(missing)
	newLines := make([]string, 0, len(lines)+len(insertion))
	newLines = append(newLines, lines[:headerIdx+1]...)
	newLines = append(newLines, insertion...)
	newLines = append(newLines, lines[headerIdx+1:]...)
	return fsatomic.WriteFile(path, []byte(strings.Join(newLines, "\n")), fsatomic.Options{FilePerm: 0o600})
}

func newUnenrollCmd() *cobra.Command {
	var configPath string
	var plan bool
	cmd := &cobra.Command{
		Use:   "unenroll",
		Short: "Leave the enrolled organization and clear local credentials",
		Long: `Leaves the organization in a fixed order that never blocks an agent session:
the enrolment is fenced first, then everything it conferred is retired (the
org budget and its requirement, signed policies, governance pins, the grant),
the organization is told (best effort), and finally the enrolment and the
credentials are removed. A running daemon admits requests at once and
recomposes onto your own settings without a restart.

--plan prints that conferred -> retired table and changes nothing. Your
config.toml and local data are kept; nothing already shared is deleted from
the org server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			if plan {
				st, serr := b.client.Status(cmd.Context())
				if serr != nil {
					return serr
				}
				printUnenrolPlan(cmd.OutOrStdout(), st.Enrolled, st.OrgName)
				return nil
			}
			rep, err := performUnenrol(cmd.Context(), b, configPath)
			if err != nil {
				return err
			}
			printUnenrolReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&plan, "plan", false, "Print what leaving would retire, in order, and change nothing")
	return cmd
}

func newOrgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "org",
		Short: "Organization enrolment status, scope, manual push, preview, backfill",
		Long: "Organization enrolment status, scope, manual push, preview and backfill.\n\n" +
			"Joining and leaving are top-level commands:\n" +
			"  observer enroll --link <enrolment link>   join an organization\n" +
			"  observer unenroll                         leave it",
		// T-746: an unknown subcommand is an error with a hint, never cobra's
		// help-and-exit-0 for a group command (an installer step that typed
		// the org-prefixed enrol verb used to "succeed" without enrolling).
		Args: orgSubcommandArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	// The verbs people reach for under `org` are the top-level commands;
	// `observer org enroll` and `observer org unenroll` run them (hidden, so
	// help keeps one name for each).
	enroll, unenroll := newEnrollCmd(), newUnenrollCmd()
	enroll.Hidden, unenroll.Hidden = true, true
	cmd.AddCommand(
		newOrgStatusCmd(),
		newOrgPushStatusCmd(),
		newOrgPushNowCmd(),
		newOrgPreviewCmd(),
		newOrgBackfillCmd(),
		newOrgResyncCmd(),
		newOrgEmitManagedSettingsCmd(),
		newOrgGrantCmd(),
		newOrgRequestCmd(),
		newOrgRequestsCmd(),
		enroll,
		unenroll,
	)
	return cmd
}

// orgSubcommandArgs refuses any positional argument `observer org` itself
// receives: cobra hands a group command the words it could not resolve to a
// subcommand, so this is the unknown-subcommand path (T-746). It is the
// generic group refusal (cmdgroups.go, T-757) plus where joining and leaving
// really live.
func orgSubcommandArgs(cmd *cobra.Command, args []string) error {
	if err := unknownSubcommandArgs(cmd, args); err != nil {
		return fmt.Errorf("%w; to join an organization run `observer enroll --link <enrolment link>`, to leave it `observer unenroll`", err)
	}
	return nil
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
			rep, err := collectOrgStatus(cmd.Context(), b)
			if err != nil {
				return err
			}
			printOrgStatus(cmd.OutOrStdout(), rep)
			// WINNODE2 item 1b: what each running daemon itself saw of its
			// credential, not this command's own view.
			if rep.State.Enrolled {
				for _, l := range daemonCredentialLines(loadLiveDaemonCredentials(cmd.Context(), filepath.Dir(b.cfg.Observer.DBPath), b.store)) {
					fmt.Fprintln(cmd.OutOrStdout(), l)
				}
			}
			// WINNODE item 4: a managed node names its machine proof, a node
			// its org switched to enterprise included (P-205).
			if managed, merr := orgclient.NodeManaged(cmd.Context(), b.store); merr == nil && managed {
				printMachineProof(cmd.Context(), cmd.OutOrStdout(), b.client, b.store)
			}
			// Lane SEC-E: the security floors and managed pull on this node.
			for _, l := range securityOrgStatusLines(cmd.Context(), configPath, b.cfg, b.store) {
				fmt.Fprintln(cmd.OutOrStdout(), l)
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

			rep, err := performOrgBackfill(cmd.Context(), b.store, confirm)
			if err != nil {
				return err
			}
			org := ""
			if enr, lerr := b.store.LoadEnrolment(cmd.Context()); lerr == nil && enr != nil {
				org = orgenrol.DisplayName(enr.OrgID, enr.OrgServerURL, enr.OrgName)
			}
			printOrgBackfillReport(cmd.OutOrStdout(), rep, org)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&all, "all", false, "rewind every table's cursor to 0 (currently the only supported scope)")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "actually rewind (omit for dry-run)")
	return cmd
}

// orgBackfillReport is what one `observer org backfill --all` run found and
// did. The CLI prints it (printOrgBackfillReport); Settings > Enrolment's
// Share history action renders it (enrolDashboard.ShareHistory). Both run
// performOrgBackfill, so the two can never count or rewind differently.
type orgBackfillReport struct {
	// Eligible is how many rows were already waiting to ship before the run.
	Eligible int64
	// WouldUnlock is how many more rows the rewind makes eligible: the rows
	// that predate enrolment (or that a previous push already shipped).
	WouldUnlock int64
	// Total is the entire local corpus across the pushable tables.
	Total int64
	// Rewound is true when the cursor was actually reset (confirm).
	Rewound bool
}

// performOrgBackfill is `observer org backfill --all`: it counts what a rewind
// would make eligible and, only when confirm is set, resets every table's push
// cursor to 0 so the push loop ships the whole local corpus over its next
// cycles. A dry run changes nothing.
func performOrgBackfill(ctx context.Context, st *store.Store, confirm bool) (orgBackfillReport, error) {
	cur, err := st.LoadPushCursor(ctx)
	if err != nil {
		return orgBackfillReport{}, fmt.Errorf("load cursor: %w", err)
	}
	// Row COUNTS on both sides (T-373): the rows above the cursor now, and
	// every row the zero cursor a rewind writes would expose.
	above, err := st.PushEligibleCounts(ctx, cur)
	if err != nil {
		return orgBackfillReport{}, fmt.Errorf("eligible counts: %w", err)
	}
	all, err := st.PushEligibleCounts(ctx, store.PushCursor{})
	if err != nil {
		return orgBackfillReport{}, fmt.Errorf("row counts: %w", err)
	}
	eligible := eligibleTotal(above)
	total := eligibleTotal(all)
	rep := orgBackfillReport{Eligible: eligible, WouldUnlock: total - eligible, Total: total}
	if !confirm {
		return rep, nil
	}
	if err := st.SavePushCursor(ctx, store.PushCursor{}); err != nil {
		return orgBackfillReport{}, fmt.Errorf("rewind cursor: %w", err)
	}
	rep.Rewound = true
	return rep, nil
}

// backfillCrossEnrolmentWarning is operator ruling D-273 item 2 (review
// M3-12): the rewind keeps shipping history captured under a previous
// enrolment, and says so before the operator confirms. Settings > Enrolment's
// Share history card shows the same warning (web/src/lib/shareHistory.ts).
func backfillCrossEnrolmentWarning(org string) string {
	if org == "" {
		org = "the organization this machine is enrolled in now"
	}
	return "WARNING: the older rows can include sessions captured under a previous enrolment " +
		"(another organization, or personal use before this machine enrolled). They all go to " + org + ", " +
		"and cannot be taken back once they are pushed."
}

// printOrgBackfillReport renders a backfill run. org names the current
// organization in the cross-enrolment warning ("" when unknown).
func printOrgBackfillReport(out io.Writer, rep orgBackfillReport, org string) {
	fmt.Fprintf(out, "currently eligible: %d rows\n", rep.Eligible)
	fmt.Fprintf(out, "would unlock:       %d more rows (entire local corpus)\n", rep.WouldUnlock)
	if rep.WouldUnlock > 0 && !rep.Rewound {
		fmt.Fprintln(out, "\n"+backfillCrossEnrolmentWarning(org))
	}
	if !rep.Rewound {
		fmt.Fprintln(out, "\nDRY RUN - pass --confirm to rewind the cursor.")
		return
	}
	fmt.Fprintln(out, "cursor reset to 0; next push cycle will ship the full corpus.")
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
		Long: `Prints the JSON of the most recent successfully pushed envelope - exactly
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
		Short: "Push any unpushed activity to the enrolled organization immediately",
		Long: `Runs one push cycle now instead of waiting for the interval. Useful to
verify enrolment end to end or to flush before shutting down.

The push carries this machine's CURRENT budget posture: the command fetches
the org budget policy first (the same verified, fail-open fetch the daemon
runs) and persists the verified document. While a daemon is running this is
a second writer of that cache, so a fenced daemon intervention (TERM/KILL
under an org cap) can be refused as "witness changed" until the daemon's own
next fetch (default 120 s) - a bounded window, documented in docs/budgets.md.

When nothing is queued the command reports the current cursor state
and the last push so the operator can tell why nothing happened -
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
			rep, err := performPushNow(cmd.Context(), b)
			if errors.Is(err, orgclient.ErrNotEnrolled) {
				return errors.New("not enrolled; run `observer enroll <org-url> <token>` first")
			}
			if err != nil {
				return err
			}
			printPushNowReport(cmd.OutOrStdout(), rep)
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
	level, text := managedBindNote(res, err)
	switch level {
	case "":
		// Older server without the managed-bind route - nothing to report.
	case "ok":
		fmt.Fprintln(out, text)
	default:
		fmt.Fprintln(out, "\n"+text)
	}
}

// managedBindNote classifies the managed machine-binding outcome into one
// tone + sentence, shared by the CLI and the dashboard. An empty level means
// there is nothing to report.
func managedBindNote(res orgcontract.ManagedBindResponse, err error) (level, text string) {
	switch {
	case errors.Is(err, orgclient.ErrManagedBindRefused):
		return "warn", "Notice: this machine is already bound to another managed node in your org. The bind was refused and your admin has been notified."
	case err != nil:
		return "warn", fmt.Sprintf("Warn: managed machine-binding could not be recorded (enrolment is unaffected): %v", err)
	case res.Collision:
		return "warn", "Notice: this machine is already bound to another managed node in your org. Your admin has been notified."
	case res.Status == orgclient.ManagedBindUnbindable:
		return "info", "Note: this host has no stable machine identity, so the managed node shows as unbound to your admin."
	case res.Status == orgclient.ManagedBindUnavailable:
		return "", ""
	default:
		return "ok", fmt.Sprintf("Bound this machine to your managed node (%s).", res.Status)
	}
}
