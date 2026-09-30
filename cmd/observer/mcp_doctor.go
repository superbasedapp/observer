package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer mcp doctor` - the node-side Agent Access probes (doc3 §15.0 /
// §15 "CLI observer mcp"; failure-mode rows of §10 that a node can see):
// relay config valid, org enrolled + reachable, agent-access registration +
// an STS token mint, each wrapped client entry still pointing at the relay,
// the launch journal consistent, the decision record chain intact. The
// probes are an ORDERED table walked top-down (CLAUDE.md #5); a probe whose
// prerequisite failed reports skip, never a guess. With the relay disabled
// no network probe runs (the kill switch) - only the stranded-journal check.

// Doctor check statuses (closed vocabulary).
const (
	mcpDoctorPass = "pass"
	mcpDoctorWarn = "warn"
	mcpDoctorFail = "fail"
	mcpDoctorSkip = "skip"
)

// mcpDoctorCheck is one probe result.
type mcpDoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// mcpDoctorReport is the JSON shape `observer mcp doctor --json` prints.
type mcpDoctorReport struct {
	Enabled bool             `json:"enabled"`
	Checks  []mcpDoctorCheck `json:"checks"`
	Failed  int              `json:"failed"`
	Warned  int              `json:"warned"`
}

// mcpDoctorDeps are the doctor's I/O seams: the SAME remote-forwarding deps
// status / enable use, plus the org liveness GET. Tests inject fakes.
type mcpDoctorDeps struct {
	remote mcpRelayRemoteDeps
	// health GETs <org>/healthz through the egress-guarded client.
	health func(ctx context.Context, orgURL string, enr *store.Enrolment) error
}

// mcpDoctorDepsFor builds the production deps (a package var so tests can
// substitute a fake org).
var mcpDoctorDepsFor = func(cfg config.Config, st *store.Store, logger *slog.Logger) mcpDoctorDeps {
	remote := defaultMCPRelayRemoteDeps(cfg, st, logger)
	return mcpDoctorDeps{remote: remote, health: func(ctx context.Context, orgURL string, enr *store.Enrolment) error {
		return mcpOrgHealth(ctx, remote.egress(orgURL, enr), orgURL)
	}}
}

// mcpOrgHealth is the org server liveness probe (GET /healthz, the
// unauthenticated liveness route).
func mcpOrgHealth(ctx context.Context, c *http.Client, orgURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(orgURL, "/")+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("GET /healthz answered %d", resp.StatusCode)
	}
	return nil
}

// contextWithMCPProbeTimeout bounds one network probe.
func contextWithMCPProbeTimeout(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	return context.WithTimeout(cmd.Context(), mcpRelayRemoteProbeTimeout)
}

// mcpDoctorEnv is the state the probes share (each probe reads what the
// earlier rows established).
type mcpDoctorEnv struct {
	ctx      context.Context
	cfg      config.Config
	database *sql.DB // nil when the DB does not exist (disabled relay)
	st       *store.Store
	rs       *record.SQLStore
	h        *mcpRelayHandle
	deps     mcpDoctorDeps
	logger   *slog.Logger

	enr       *store.Enrolment
	reachable bool
	tokens    *mcprelay.TokenClient
	remote    mcpRelayRemote
	specs     []record.LaunchSpec
	specsErr  error
}

// mcpDoctorProbe is one row of the ordered probe table. run returns one or
// more checks (the per-client row fans out).
type mcpDoctorProbe struct {
	name string
	// needsEnabled rows are skipped (no I/O) when the relay is disabled.
	needsEnabled bool
	run          func(e *mcpDoctorEnv) []mcpDoctorCheck
}

// mcpDoctorOne wraps one check as a probe result.
func mcpDoctorOne(name, status, detail string) []mcpDoctorCheck {
	return []mcpDoctorCheck{{Name: name, Status: status, Detail: detail}}
}

// mcpDoctorProbes is the ordered probe table (top-down, one test per row).
var mcpDoctorProbes = []mcpDoctorProbe{
	{name: "relay.config", run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		m := e.cfg.MCPRelay
		return mcpDoctorOne("relay.config", mcpDoctorPass, fmt.Sprintf("[mcp_relay] loaded and validated: enabled=%v mode=%s audit=%s listen=%q gateway_url=%q", m.Enabled, m.Mode, m.AuditMode, m.Listen, m.GatewayURL))
	}},
	{name: "relay.enabled", run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		if !e.cfg.MCPRelay.Enabled {
			return mcpDoctorOne("relay.enabled", mcpDoctorSkip, "the relay is disabled ([mcp_relay].enabled = false): no org / STS / client probe runs (enable with `observer mcp-relay enable`)")
		}
		return mcpDoctorOne("relay.enabled", mcpDoctorPass, "[mcp_relay].enabled = true")
	}},
	{name: "org.enrolled", needsEnabled: true, run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		enr, err := e.st.LoadEnrolment(e.ctx)
		if err != nil {
			return mcpDoctorOne("org.enrolled", mcpDoctorFail, "enrolment unreadable: "+err.Error())
		}
		if enr == nil {
			return mcpDoctorOne("org.enrolled", mcpDoctorFail, "not enrolled: the relay's grant, STS and gateway all come from the org (run `observer org enroll`)")
		}
		e.enr = enr
		return mcpDoctorOne("org.enrolled", mcpDoctorPass, fmt.Sprintf("org %s at %s (tenancy %s)", enr.OrgID, enr.OrgServerURL, tenancyOrIndividual(enr.Tenancy)))
	}},
	{name: "org.reachable", needsEnabled: true, run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		if e.enr == nil {
			return mcpDoctorOne("org.reachable", mcpDoctorSkip, "not enrolled")
		}
		ctx, cancel := context.WithTimeout(e.ctx, mcpRelayRemoteProbeTimeout)
		defer cancel()
		if err := e.deps.health(ctx, e.enr.OrgServerURL, e.enr); err != nil {
			return mcpDoctorOne("org.reachable", mcpDoctorFail, "org server unreachable: "+err.Error())
		}
		e.reachable = true
		return mcpDoctorOne("org.reachable", mcpDoctorPass, e.enr.OrgServerURL+"/healthz answered 2xx")
	}},
	{name: "table.loaded", needsEnabled: true, run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		t := e.h.Table()
		if t == nil {
			return mcpDoctorOne("table.loaded", mcpDoctorWarn, "no tools.mcp_access table accepted yet (cache "+e.h.cache.Path+"): the daemon fetches it from the org; until then no stdio entry can be wrapped")
		}
		return mcpDoctorOne("table.loaded", mcpDoctorPass, fmt.Sprintf("version=%d mode=%s rows=%d vservers=%d issuer=%s", t.Meta.Version, t.Mode, len(t.Node.Rows), len(t.Node.Registry.VServers), t.Node.Registry.Issuer))
	}},
	{name: "sts.registered", needsEnabled: true, run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		switch {
		case e.enr == nil:
			return mcpDoctorOne("sts.registered", mcpDoctorSkip, "not enrolled")
		case !e.reachable:
			return mcpDoctorOne("sts.registered", mcpDoctorSkip, "org server unreachable")
		case e.h.Table() == nil:
			return mcpDoctorOne("sts.registered", mcpDoctorSkip, "no table: STS issuer unknown")
		}
		ctx, cancel := context.WithTimeout(e.ctx, mcpRelayRemoteProbeTimeout)
		defer cancel()
		e.tokens, _, e.remote = resolveMCPRelayRemote(ctx, e.cfg, e.st, e.h, e.deps.remote, e.logger)
		if !e.remote.Wired {
			return mcpDoctorOne("sts.registered", mcpDoctorFail, e.remote.Reason)
		}
		detail := fmt.Sprintf("agent-access credential %s gen %d machine_fp %s (issuer %s)", e.remote.CredentialID, e.remote.CredGen, e.remote.MachineFP, e.remote.Issuer)
		if e.deps.remote.keys != nil {
			if keys, err := e.deps.remote.keys(); err == nil {
				if loc := orgclient.AgentAccessKeyLocation(keys); loc != "" {
					detail += "; key store: " + loc
				}
			}
		}
		return mcpDoctorOne("sts.registered", mcpDoctorPass, detail)
	}},
	{name: "sts.mint", needsEnabled: true, run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		if e.tokens == nil {
			return mcpDoctorOne("sts.mint", mcpDoctorSkip, "no registered token client")
		}
		aud := mcpDoctorAudience(e.h)
		if aud == "" {
			return mcpDoctorOne("sts.mint", mcpDoctorSkip, "the table names no vserver to mint for")
		}
		ctx, cancel := context.WithTimeout(e.ctx, mcpRelayRemoteProbeTimeout)
		defer cancel()
		tok, err := e.tokens.Token(ctx, aud, "")
		if err != nil {
			return mcpDoctorOne("sts.mint", mcpDoctorFail, "token exchange for "+aud+" failed: "+err.Error())
		}
		// The token itself is never printed or stored; only its shape.
		return mcpDoctorOne("sts.mint", mcpDoctorPass, fmt.Sprintf("DPoP-bound token minted for %s (expires %s, jkt %s)", aud, tok.ExpiresAt.UTC().Format("15:04:05Z"), mcpShortID(tok.JKT)))
	}},
	{name: "clients.wrapped", needsEnabled: true, run: mcpDoctorClients},
	{name: "journal.consistent", run: mcpDoctorJournal},
	{name: "record.chain", needsEnabled: true, run: func(e *mcpDoctorEnv) []mcpDoctorCheck {
		vr, key, err := mcpDoctorVerifyChain(e)
		if err != nil {
			return mcpDoctorOne("record.chain", mcpDoctorFail, "decision record unreadable: "+err.Error())
		}
		if !vr.OK() {
			return mcpDoctorOne("record.chain", mcpDoctorFail, "decision record chain TAMPER: "+vr.Fault.Error()+" (genesis identity "+key+")")
		}
		status, detail := mcpDoctorPass, fmt.Sprintf("%d record(s) verified from genesis identity %s, head seq %d", vr.Records, key, vr.HeadSeq)
		if pl, perr := e.rs.PendingLoss(e.ctx, record.DefaultFamily); perr == nil && pl.Count > 0 {
			status, detail = mcpDoctorWarn, detail+fmt.Sprintf("; %d local append(s) pending as a gap record", pl.Count)
		}
		return mcpDoctorOne("record.chain", status, detail)
	}},
}

// mcpDoctorVerifyChain verifies the decision record from its genesis. The
// chain's genesis identity is mcpRelayNodeKey (the one the daemon and the
// wrapper append under): "member:<id>" once enrolled, "node:<db path>"
// before. A chain begun before this node enrolled therefore verifies only
// from the pre-enrolment identity, so both legitimate identities are tried
// (enrolled first) and the one that verifies is reported; a chain that
// verifies from neither is a real fault, reported against the first.
func mcpDoctorVerifyChain(e *mcpDoctorEnv) (record.VerifyResult, string, error) {
	keys := []string{mcpRelayNodeKey(e.ctx, e.cfg, e.st)}
	if pre := "node:" + e.cfg.Observer.DBPath; pre != keys[0] {
		keys = append(keys, pre)
	}
	var first record.VerifyResult
	for i, k := range keys {
		vr, err := record.NewSQLStore(e.database, k).Verify(e.ctx)
		if err != nil {
			return record.VerifyResult{}, k, err
		}
		if vr.OK() {
			return vr, k, nil
		}
		if i == 0 {
			first = vr
		}
	}
	return first, keys[0], nil
}

func tenancyOrIndividual(t string) string {
	if t == "" {
		return "individual"
	}
	return t
}

func mcpShortID(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// mcpDoctorAudience is the audience the mint probe asks for: the first
// vserver by id (deterministic).
func mcpDoctorAudience(h *mcpRelayHandle) string {
	t := h.Table()
	if t == nil || len(t.Node.Registry.VServers) == 0 {
		return ""
	}
	vs := slices.Clone(t.Node.Registry.VServers)
	sort.Slice(vs, func(i, j int) bool { return vs[i].ID < vs[j].ID })
	return t.Node.Registry.AudienceOf(vs[0])
}

// mcpDoctorClientFacts is what the per-client rule table decides on.
type mcpDoctorClientFacts struct {
	tool         string
	configExists bool
	verified     bool // current bytes == the applied digest of a journal row
	unmediated   int  // stdio entries a preview shows run direct
	rows         int
}

// mcpDoctorClientRule is one ordered row: first match wins.
type mcpDoctorClientRule struct {
	name   string
	match  func(f mcpDoctorClientFacts) bool
	status string
	detail func(f mcpDoctorClientFacts) string
}

// mcpDoctorClientRules decides one journaled client's row.
var mcpDoctorClientRules = []mcpDoctorClientRule{
	{
		name: "config_gone", status: mcpDoctorFail,
		match:  func(f mcpDoctorClientFacts) bool { return !f.configExists },
		detail: func(f mcpDoctorClientFacts) string { return "the journaled client config no longer exists" },
	},
	{
		name: "direct_entries", status: mcpDoctorWarn,
		match: func(f mcpDoctorClientFacts) bool { return f.unmediated > 0 },
		detail: func(f mcpDoctorClientFacts) string {
			return fmt.Sprintf("%d stdio entr%s run DIRECT, unmediated (no approved binding, or not yet wrapped: run `observer mcp wrap`)", f.unmediated, mcpPlural(f.unmediated, "y", "ies"))
		},
	},
	{
		name: "edited_since", status: mcpDoctorWarn,
		match: func(f mcpDoctorClientFacts) bool { return !f.verified },
		detail: func(f mcpDoctorClientFacts) string {
			return "config edited since the projection (not the bytes the relay wrote); its stdio entries still spawn the relay"
		},
	},
	{
		name: "wrapped", status: mcpDoctorPass,
		match: func(mcpDoctorClientFacts) bool { return true },
		detail: func(f mcpDoctorClientFacts) string {
			return fmt.Sprintf("%d journaled entr%s, config unchanged since the projection; every stdio entry spawns the relay", f.rows, mcpPlural(f.rows, "y", "ies"))
		},
	},
}

func mcpPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// mcpDoctorClientCheck walks mcpDoctorClientRules for one client.
func mcpDoctorClientCheck(f mcpDoctorClientFacts) mcpDoctorCheck {
	for _, r := range mcpDoctorClientRules {
		if r.match(f) {
			return mcpDoctorCheck{Name: "client:" + f.tool, Status: r.status, Detail: r.detail(f)}
		}
	}
	return mcpDoctorCheck{Name: "client:" + f.tool, Status: mcpDoctorFail, Detail: "no rule matched"}
}

// mcpDoctorClients is the per-client "entry points at the relay" probe: the
// SAME verified-applied predicate the coverage matrix reads plus the same
// Stage-only preview (nothing written).
func mcpDoctorClients(e *mcpDoctorEnv) []mcpDoctorCheck {
	if e.specsErr != nil {
		return mcpDoctorOne("clients.wrapped", mcpDoctorFail, "launch journal unreadable: "+e.specsErr.Error())
	}
	if len(e.specs) == 0 {
		return mcpDoctorOne("clients.wrapped", mcpDoctorWarn, "no client config is projected yet (run `observer mcp wrap`)")
	}
	applied := mcpRelayAppliedState(e.ctx, e.rs)
	unmediated := mcpRelayUnmediatedStdio(e.ctx, e.cfg, e.h, e.remote.Wired)
	byTool := map[string]*mcpDoctorClientFacts{}
	for _, s := range e.specs {
		f, ok := byTool[s.Client]
		if !ok {
			f = &mcpDoctorClientFacts{
				tool: s.Client, configExists: true, unmediated: unmediated[s.Client],
				verified: applied.StdioApplied(s.Client) || applied.RemoteApplied(s.Client),
			}
			byTool[s.Client] = f
		}
		f.rows++
		if _, err := os.Stat(s.ConfigPath); err != nil {
			f.configExists = false
		}
	}
	tools := make([]string, 0, len(byTool))
	for t := range byTool {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	out := make([]mcpDoctorCheck, 0, len(tools))
	for _, t := range tools {
		out = append(out, mcpDoctorClientCheck(*byTool[t]))
	}
	return out
}

// mcpDoctorJournal checks every launch-journal row: the backup is present
// and hashes to its recorded digest (a restore would otherwise refuse), a
// stdio row carries its approved binding (the wrapper refuses an unbound
// row), the row carries an applied digest, and - with the relay disabled -
// that no row is stranded (a wrapped entry the wrapper now refuses).
func mcpDoctorJournal(e *mcpDoctorEnv) []mcpDoctorCheck {
	if e.specsErr != nil {
		return mcpDoctorOne("journal.consistent", mcpDoctorFail, "launch journal unreadable: "+e.specsErr.Error())
	}
	if len(e.specs) == 0 {
		return mcpDoctorOne("journal.consistent", mcpDoctorPass, "launch journal empty")
	}
	var fails, warns []string
	if !e.cfg.MCPRelay.Enabled {
		fails = append(fails, fmt.Sprintf("%d row(s) still wrap client configs while the relay is disabled - the wrapper refuses to start them; run `observer mcp unwrap`", len(e.specs)))
	}
	for _, s := range e.specs {
		id := s.Client + "/" + s.EntryKey
		raw, err := os.ReadFile(s.BackupPath)
		switch {
		case err != nil:
			fails = append(fails, id+": backup unreadable ("+err.Error()+"), restore will refuse")
		case mcprelay.HashBytes(raw) != s.BackupSHA256:
			fails = append(fails, id+": backup hash mismatch (tampered), restore will refuse")
		}
		if s.OrigCommand != project.RemoteOrigCommand && s.VServer == "" {
			fails = append(fails, id+": stdio row has no approved vserver binding - "+errMCPRelayUnbound.Error())
		}
		if s.AppliedSHA256 == "" {
			warns = append(warns, id+": no applied digest (pre-132 row): restore reverses entries instead of a byte-identical rewrite")
		}
	}
	switch {
	case len(fails) > 0:
		return mcpDoctorOne("journal.consistent", mcpDoctorFail, strings.Join(append(fails, warns...), "; "))
	case len(warns) > 0:
		return mcpDoctorOne("journal.consistent", mcpDoctorWarn, strings.Join(warns, "; "))
	}
	return mcpDoctorOne("journal.consistent", mcpDoctorPass, fmt.Sprintf("%d row(s): backups present and hash-verified, every stdio row bound", len(e.specs)))
}

// runMCPDoctor walks the probe table over an assembled environment.
func runMCPDoctor(e *mcpDoctorEnv) mcpDoctorReport {
	rep := mcpDoctorReport{Enabled: e.cfg.MCPRelay.Enabled}
	for _, p := range mcpDoctorProbes {
		var checks []mcpDoctorCheck
		switch {
		case p.needsEnabled && !e.cfg.MCPRelay.Enabled:
			continue // reported once by relay.enabled; no I/O
		case e.database == nil && p.name != "relay.config" && p.name != "relay.enabled":
			checks = mcpDoctorOne(p.name, mcpDoctorSkip, "no node database yet")
		default:
			checks = p.run(e)
		}
		for _, c := range checks {
			switch c.Status {
			case mcpDoctorFail:
				rep.Failed++
			case mcpDoctorWarn:
				rep.Warned++
			}
			rep.Checks = append(rep.Checks, c)
		}
	}
	return rep
}

func newMCPDoctorCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Node probes: relay config, org enrolled + reachable, STS registration + token mint, wrapped client entries, journal, record chain",
		Long: "Runs the node-side Agent Access probes top-down and prints one line per\n" +
			"check (pass / warn / fail / skip): [mcp_relay] valid, enrolled with an\n" +
			"org that answers /healthz, the agent-access registration, ONE STS token\n" +
			"mint for the first approved vserver (the token is never printed or\n" +
			"stored), every journaled client config still routing its stdio entries\n" +
			"through the relay, the launch journal's backups and bindings, and the\n" +
			"hash-chained decision record. Exits non-zero when any check fails.\n\n" +
			"With [mcp_relay].enabled = false no network probe runs; it only checks\n" +
			"that no client config is left wrapped.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadMCPNodeConfig(configPath)
			if err != nil {
				return err
			}
			logger := slog.New(slog.DiscardHandler)
			e := &mcpDoctorEnv{ctx: cmd.Context(), cfg: cfg, logger: logger}
			if cfg.MCPRelay.Enabled || dbFileExists(cfg) {
				_, database, cleanup, derr := loadConfigAndDB(cmd.Context(), configPath)
				if derr != nil {
					return derr
				}
				defer cleanup()
				e.database = database
				e.st = store.New(database)
				e.rs = record.NewSQLStore(database, "")
				e.specs, e.specsErr = e.rs.ListLaunchSpecs(cmd.Context())
			}
			e.h = newMCPRelayHandle(cfg, e.st, nil, logger)
			if cfg.MCPRelay.Enabled {
				e.deps = mcpDoctorDepsFor(cfg, e.st, logger)
			}
			rep := runMCPDoctor(e)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL")
				for _, c := range rep.Checks {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", strings.ToUpper(c.Status), c.Name, c.Detail)
				}
				_ = tw.Flush()
				fmt.Fprintf(cmd.OutOrStdout(), "\n%d failed, %d warning(s)\n", rep.Failed, rep.Warned)
			}
			if rep.Failed > 0 {
				return errors.New("observer mcp doctor: " + fmt.Sprint(rep.Failed) + " check(s) failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON")
	return cmd
}
