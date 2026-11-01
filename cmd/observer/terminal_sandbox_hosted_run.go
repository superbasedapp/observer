//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_hosted_run.go is the daemon side of a hosted run (lane
// SBX-P7): Create checks everything that can be checked without the vendor
// (the floors, the local probe, the tier, the custody, the tool delivery,
// the upload manifest, the consent and the spend cap) and refuses by name;
// Attach writes the run record and a plan file and returns the PTY child's
// argv. The PTY child (`observer sandbox-hosted-host`, terminal_sandbox_
// hosted_host.go) is the only process that reads the credential and calls
// the vendor, and only for this user-launched run (I6).

// The hosted driver's helper verbs and markers.
const (
	hostedHostVerb    = "sandbox-hosted-host"
	hostedInnerMarker = "observer-hosted-inner"
	hostedPlanVersion = 1
)

// The hosted launch refusals (copy keys a surface renders).
const (
	verdictHostedConsentRequired = sandboxselect.VerdictConsentRequired
	verdictHostedCustody         = sandboxselect.VerdictCustodyUnsatisfiable
	verdictHostedTool            = sandboxselect.VerdictToolUnavailableInImage
)

// hostedPlanFile is the per-run plan the host helper reads. It holds no
// secret by rule (TestHostedPlanFileHoldsNoSecrets): the credential is read
// by the helper at use time.
type hostedPlanFile struct {
	Version  int    `json:"version"`
	RunID    string `json:"run_id"`
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	// EndpointSPKISHA256 is the endpoint's server key pin ("" for none):
	// the credential must have been connected with it (SBX-GOV-4).
	EndpointSPKISHA256 string `json:"endpoint_spki_sha256,omitempty"`
	Region             string `json:"region"`
	Template           string `json:"template"`
	Tier               string `json:"tier"`
	Custody            string `json:"custody"`
	// TimeoutMinutes is the vendor timeout (the spend cap's answer).
	TimeoutMinutes int `json:"timeout_minutes"`
	// Root is the host workspace; Files the manifest the user consented to
	// (re-listed and compared by the helper before upload).
	Root     string                       `json:"root"`
	ScopeKey string                       `json:"scope_key"`
	Files    []sandboxremote.ManifestFile `json:"files"`
	// BoxBinary is the host path of the in-box observer to upload.
	BoxBinary string `json:"box_binary"`
	// ToolStateRel are the tool's HOME-relative state dirs (pulled at each
	// checkpoint and at teardown).
	ToolStateRel []string `json:"tool_state_rel"`
	// ToolInstall is the tool's grounded Linux install argv run at first
	// start (only on the internet tier with no template); empty otherwise.
	ToolInstall []string `json:"tool_install,omitempty"`
	// ForwardEnv are the provider API-key variable names copied into the
	// box (custody in_box_api_key only; values are read by the helper).
	ForwardEnv        []string `json:"forward_env,omitempty"`
	CheckpointMinutes int      `json:"checkpoint_minutes"`
	DailyBoxMinutes   int      `json:"daily_box_minutes"`
	// DBExport is [terminal.sandbox.hosted].db_export (opt-in, ruling
	// P-141): the teardown exports the box's SQLite stores only when set.
	// RetentionDays is [terminal.sandbox].workspace_retention_days, the
	// horizon the teardown sweeps earlier runs' copies by (0 keeps them).
	DBExport      bool   `json:"db_export,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`
	ObserverDir   string `json:"observer_dir"`
	Tool          string `json:"tool"`
}

// hostedForwardEnvNames are the provider API-key variables an
// in_box_api_key run copies into the box when the launch environment holds
// them (a provider table, never a tool name).
var hostedForwardEnvNames = []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"}

// hostedChoice is what Create decided for Attach.
type hostedChoice struct {
	plan hostedPlanFile
}

// hostedChoices holds each created run's choice until Attach.
var hostedChoices sync.Map

// hostedTier is the egress tier of a hosted run (the resolved profile's).
func (d *hostedDriver) tier() vocab.Tier {
	t := vocab.Tier(d.r.egress.Mode)
	if t == "" {
		t = vocab.TierInternet
	}
	return t
}

// floor refuses a launch the local config or an org floor does not allow
// on this row.
func (d *hostedDriver) floor(cfg config.TerminalSandboxConfig, tier vocab.Tier, custody vocab.KeyCustody, region string) error {
	row, _ := sandboxbackend.Get(d.vendor.ID)
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	if !slices.Contains(sandboxEnabledBackends(cfg), d.vendor.ID) {
		return fmt.Errorf("terminal_sandbox: %s is not in [terminal.sandbox].backends %v; a hosted sandbox is used only when listed", d.vendor.ID, cfg.Backends)
	}
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: %s builds %s isolation, below [terminal.sandbox].min_isolation = %s", d.vendor.ID, row.Iso.Class, floor)
	}
	if !row.OffersTier(tier) {
		return fmt.Errorf("terminal_sandbox: %s: %s has no %s network tier (a hosted box cannot use the host network); set [terminal.sandbox].egress to internet, proxy_only or none", sandboxselect.VerdictEgressUnsupported, d.vendor.Name, tier)
	}
	// A host allow-list cannot be honoured by a hosted box (the LEFT-SBX
	// merge, audit finding 4): its egress is the vendor's, block-all or
	// allow-all, never Observer's gateway. On the internet tier it would
	// reach every host, so while the list (or an org pin that left no host
	// in common) is set, the launch is refused naming the key; proxy_only
	// and none block the box's own egress and are unaffected.
	if key := hostedEgressHostsKey(cfg); key != "" && tier == vocab.TierInternet {
		return fmt.Errorf("terminal_sandbox: %s: %s is set, and %s's box egress on the internet tier is the vendor's own and reaches every host, so it cannot honour a host list; use the proxy_only or none tier with this row, or a local row whose gateway applies the list", sandboxselect.VerdictEgressUnsupported, key, d.vendor.Name)
	}
	floors := sandboxOrgFloors()
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: row.ID, Tier: tier, Interactive: true, Custody: custody, Region: region, AcceptReducedCapture: true, ProviderDirect: cfg.EffectiveProviderDirect()},
		Host:    sandboxHostKind(), Floors: floors,
		// Consent is checked on its own, with the fact that changed named
		// (Create); here only the org's floors decide.
		Probes: map[string]sandboxselect.Probe{row.ID: {ConsentRecorded: true}},
		Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: hostedCredentialInReach(custody)},
	}
	if drop, dropped := sandboxselect.FloorDrop(row, in, true); dropped {
		return sandboxRefusalError{msg: isolationFloorMessage(drop)}
	}
	return nil
}

// hostedEgressHostsKey names the setting that asks for a host allow-list
// on the agent's egress: the org pin that left no host in common
// (PinnedNoEgressHost), else [terminal.sandbox].egress_allow_hosts when it
// lists any host; "" when neither is set.
func hostedEgressHostsKey(cfg config.TerminalSandboxConfig) string {
	if cfg.PinnedNoEgressHost != "" {
		return "your organization's pin of " + cfg.PinnedNoEgressHost + " (no host in common with this machine's list)"
	}
	if len(cfg.EgressAllowHosts) > 0 {
		return "[terminal.sandbox].egress_allow_hosts"
	}
	return ""
}

// custodyCheck refuses a custody this node cannot satisfy (S7d): home_relay
// needs a key the proxy injects (a routing key pool or the org gateway
// route); in_box_oauth_seed needs the auth seed projection, not built for
// hosted rows yet; provider_injected is offered by no hosted row.
func hostedCustodyCheck(homeRelayOK bool, custody vocab.KeyCustody) error {
	switch custody {
	case vocab.CustodyHomeRelay:
		if homeRelayOK {
			return nil
		}
		return fmt.Errorf("terminal_sandbox: %s: key custody home_relay keeps the model credential on this machine, which works only for a key the proxy adds itself (a [routing].key_pool key or the org AI Gateway route), and neither is configured; choose in_box_api_key in Terminals > Settings > Hosted sandboxes (disclosed before the first upload)", verdictHostedCustody)
	case vocab.CustodyInBoxAPIKey:
		return nil
	case vocab.CustodyInBoxOAuthSeed:
		return fmt.Errorf("terminal_sandbox: %s: copying a subscription login into a hosted box is not built yet; use in_box_api_key or home_relay", verdictHostedCustody)
	}
	return fmt.Errorf("terminal_sandbox: %s: key custody %s is not offered by any hosted row", verdictHostedCustody, custody)
}

// hostedCustodyCheckNoted is hostedCustodyCheck with the node's reason
// credential injection cannot serve home_relay appended (audit F10), so the
// refusal names it rather than leaving a later bare 401.
func hostedCustodyCheckNoted(homeRelayOK bool, note string, custody vocab.KeyCustody) error {
	err := hostedCustodyCheck(homeRelayOK, custody)
	if err != nil && note != "" && custody == vocab.CustodyHomeRelay {
		return fmt.Errorf("%w; %s", err, note)
	}
	return err
}

// hostedToolDelivery decides how the agent tool reaches the box (SBX-IMG-1,
// orchestrator default): no agent CLI is uploaded; a template the user
// named holds it, or, on the internet tier only, it installs from its
// vendor at first start; otherwise tool_unavailable_in_image (S11).
//
// rule is the vendor's template rule (Vendor.TemplateRule), named in the
// refusal so a vendor whose templates are restricted says how to make one.
func hostedToolDelivery(tool, template string, tier vocab.Tier, rule string) ([]string, error) {
	if strings.TrimSpace(template) != "" {
		return nil, nil
	}
	install := hostedToolInstallCommand(tool)
	if tier == vocab.TierInternet && len(install) > 0 {
		return install, nil
	}
	if len(install) == 0 {
		return nil, fmt.Errorf("terminal_sandbox: %s: %s has no grounded Linux install command, and no template is set; name a template that holds it in [terminal.sandbox.hosted.<provider>].template", verdictHostedTool, tool)
	}
	if rule != "" {
		return nil, fmt.Errorf("terminal_sandbox: %s: no template is set, and the %s tier cannot reach %s's vendor to install it at first start; %s", verdictHostedTool, tier, tool, rule)
	}
	return nil, fmt.Errorf("terminal_sandbox: %s: no template is set, and the %s tier cannot reach %s's vendor to install it at first start; name a template that holds it in [terminal.sandbox.hosted.<provider>].template, or use the internet tier", verdictHostedTool, tier, tool)
}

// hostedToolInstallCommand is the tool's grounded Linux install argv from
// the integration registry (nil when none is grounded): an npm or vendor
// script channel only, the two that run inside a plain Linux box.
func hostedToolInstallCommand(tool string) []string {
	spec, ok := integration.For(tool)
	if !ok || spec.Binary == nil {
		return nil
	}
	for _, h := range spec.Binary.Installs {
		if (h.OS == "" || h.OS == "linux") && (h.Channel == "npm" || h.Channel == "script") && len(h.Argv) > 0 {
			return append([]string(nil), h.Argv...)
		}
	}
	return nil
}

// hostedListWorkspace lists the upload candidates: git's tracked plus
// untracked-not-ignored files under root (the hardened read-only git
// envelope), each lstat'd, never followed.
var hostedListWorkspace = func(ctx context.Context, root string) ([]sandboxremote.Candidate, bool, error) {
	top, _, err := gitview.RunReadOnlyEnv(ctx, root, 4096, 20*time.Second, extrun.GitHardeningEnv(""), "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, false, nil
	}
	if t := strings.TrimSpace(string(top)); filepath.Clean(t) != filepath.Clean(root) {
		return nil, false, fmt.Errorf("terminal_sandbox: the workspace %s is inside the repository %s; launch from the repository root to upload it", root, t)
	}
	out, over, err := gitview.RunReadOnlyEnv(ctx, root, 64<<20, 60*time.Second, extrun.GitHardeningEnv(""), "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, true, fmt.Errorf("terminal_sandbox: list the workspace files: %w", err)
	}
	if over {
		return nil, true, fmt.Errorf("terminal_sandbox: %w: the workspace file list is over 64 MiB", sandboxremote.ErrScopeTooLarge)
	}
	var cands []sandboxremote.Candidate
	seen := map[string]bool{}
	for _, p := range bytes.Split(out, []byte{0}) {
		rel := string(p)
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		c := sandboxremote.Candidate{Path: rel, Kind: sandboxremote.KindOther}
		if fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			switch {
			case fi.Mode()&fs.ModeSymlink != 0:
				c.Kind = sandboxremote.KindSymlink
			case fi.Mode().IsRegular():
				c.Kind, c.Size = sandboxremote.KindRegular, fi.Size()
			case fi.IsDir():
				c.Kind = sandboxremote.KindDir
			}
		}
		cands = append(cands, c)
	}
	return cands, true, nil
}

// hostedManifest plans the upload of root.
func (d *hostedDriver) manifest(ctx context.Context, root string) (sandboxremote.Manifest, error) {
	home, _ := os.UserHomeDir()
	if h, err := filepath.EvalSymlinks(home); err == nil {
		home = h
	}
	cands, repo, err := hostedListWorkspace(ctx, root)
	if err != nil {
		return sandboxremote.Manifest{}, err
	}
	m, err := sandboxremote.PlanManifest(sandboxremote.ManifestInput{
		Root: filepath.ToSlash(root), Home: filepath.ToSlash(home), Repository: repo, Candidates: cands,
	})
	if err != nil {
		return m, fmt.Errorf("terminal_sandbox: %w", err)
	}
	return m, nil
}

// launchFacts are the consent facts of one launch.
func (d *hostedDriver) launchFacts(tier vocab.Tier, m sandboxremote.Manifest) (sandboxremote.ConsentFacts, bool) {
	f, ok := d.consentFactsStatic()
	f.Tier, f.Capture, f.ScopeKey = string(tier), hostedConsentCapture(d.vendor.ID, tier, vocab.KeyCustody(d.cfg.KeyCustody)), m.ScopeKey
	return f, ok
}

// hostedConsentCapture is the capture level the consent screen states: the
// level the row, tier and custody compute for a proxy-routed agent (a run
// whose tool is not routed records its own, lower level in its evidence).
func hostedConsentCapture(id string, tier vocab.Tier, custody vocab.KeyCustody) string {
	return sandboxselect.CaptureLabel(hostedRunCapture(id, tier, custody, true))
}

// Create runs every check the vendor is not needed for and records the
// run's plan for Attach. Nothing here reads a credential value or calls the
// vendor.
func (d *hostedDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	tier := d.tier()
	custody := vocab.KeyCustody(d.cfg.KeyCustody)
	pc := hostedVendorConfig(d.cfg, d.vendor.ID)
	region, endpoint, ok := hostedResolve(d.vendor, pc)
	if !ok {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s: %s", verdictHostedRegionUnknown, hostedResolveRefusal(d.vendor, pc))
	}
	if err := d.floor(launchFloorConfig(d.r.cfg, string(tier)), tier, custody, region); err != nil {
		return termsvc.CreateResult{}, err
	}
	if p := d.probe(ctx); p.Verdict != sandboxselect.VerdictAvailable {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s is not available: %s: %s", d.vendor.ID, p.Verdict, p.Reason)
	}
	if err := hostedCustodyCheckNoted(d.homeRelayOK, d.homeRelayNote, custody); err != nil {
		return termsvc.CreateResult{}, err
	}
	install, err := hostedToolDelivery(req.Tool, pc.Template, tier, d.vendor.TemplateRule)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	spec, _ := integration.For(req.Tool)
	if len(spec.Sandbox.StateRW) == 0 {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: tool %q is not sandbox-launchable: %s", req.Tool, spec.Sandbox.Note)
	}
	if src := strings.TrimSpace(req.WorkspaceSource); src != "" && src != "live" {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s: a hosted box receives the live workspace as an upload; the %s source is not offered", sandboxselect.VerdictSourceUnsupported, src)
	}
	m, err := d.manifest(ctx, req.ProjectRoot)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	routed, _ := d.r.launchRouted(req.Tool, req.ProjectRoot, req.ToolArgs)
	capture := hostedRunCapture(d.vendor.ID, tier, custody, routed)
	facts, _ := d.launchFacts(tier, m)
	if v := sandboxremote.CheckConsent(hostedLoadConsent(d.r.observerDir, d.vendor.ID), facts); v != sandboxremote.ConsentOK {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s (%s): review what leaves this machine and agree in Terminals > Settings > Hosted sandboxes, or run `observer sandbox hosted consent %s`", verdictHostedConsentRequired, v, d.vendor.ID)
	}
	minutes, err := sandboxremote.PlanTimeout(d.cfg.MaxRunMinutes, d.cfg.DailyBoxMinutes, hostedLedgerUsed(d.r.observerDir, d.vendor.ID, d.now(), d.cfg.DailyBoxMinutes))
	if err != nil {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %w", err)
	}
	minutes = hostedBoxMinutes(d.vendor, minutes)
	ws, err := d.r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	var forward []string
	if custody == vocab.CustodyInBoxAPIKey {
		forward = hostedForwardEnvNames
	}
	plan := hostedPlanFile{
		Version: hostedPlanVersion, RunID: ws.id, Provider: d.vendor.ID, Endpoint: endpoint, EndpointSPKISHA256: pc.EndpointSPKISHA256, Region: region,
		Template: pc.Template, Tier: string(tier), Custody: string(custody), TimeoutMinutes: minutes,
		Root: m.Root, ScopeKey: m.ScopeKey, Files: m.Files, BoxBinary: hostedBoxBinaryPath(pc, d.r.observerBin),
		ToolStateRel: spec.Sandbox.StateRW, ToolInstall: install, ForwardEnv: forward,
		CheckpointMinutes: d.cfg.CheckpointMinutes, DailyBoxMinutes: d.cfg.DailyBoxMinutes, ObserverDir: d.r.observerDir, Tool: req.Tool,
		DBExport: d.cfg.DBExport, RetentionDays: d.r.cfg.WorkspaceRetentionDays,
	}
	hostedChoices.Store(ws.id, hostedChoice{plan: plan})
	iso := termrun.Isolation{
		Class: string(hostedRow(d.vendor.ID).Iso.Class), Stack: []string{d.vendor.ID}, EgressTier: string(tier),
		CaptureLevel: string(capture.Level), CaptureRule: capture.Rule,
		CaptureOrigin: string(vocab.OriginRemoteSandbox), KeyCustody: string(custody),
	}
	if v, ok := hostedRow(d.vendor.ID).VerificationOn(sandboxHostKind()); ok {
		iso.Verification = string(v.Kind)
	}
	return termsvc.CreateResult{
		Run: termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note: fmt.Sprintf("sandbox: backend=%s region=%s egress=%s capture=%s upload=%s timeout=%dm",
			d.vendor.ID, region, tier, sandboxselect.CaptureLabel(capture), m.Summary(), minutes),
		Isolation: iso, ProxyRouted: routed,
	}, nil
}

// hostedRow returns a hosted registry row.
func hostedRow(id string) sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(id)
	return row
}

// hostedRunCapture is the computed capture of a hosted run.
func hostedRunCapture(id string, tier vocab.Tier, custody vocab.KeyCustody, routed bool) sandboxselect.CaptureResult {
	return sandboxselect.ComputeCapture(sandboxselect.CaptureInput{
		Row: hostedRow(id), Tier: tier, Custody: custody,
		ProxyRouted: routed, CredentialInReach: hostedCredentialInReach(custody),
	})
}

// hostedBoxBinaryPath is the host path of the in-box observer.
func hostedBoxBinaryPath(pc config.TerminalSandboxHostedProviderConfig, observerBin string) string {
	if b := strings.TrimSpace(pc.BoxBinary); b != "" {
		return b
	}
	return observerBin
}

// Attach writes the run record and the plan file, and returns the helper
// argv the PTY child runs.
func (d *hostedDriver) Attach(_ context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	v, ok := hostedChoices.LoadAndDelete(created.Run.ID)
	if !ok {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: run %s has no hosted plan (Create did not run)", created.Run.ID)
	}
	plan := v.(hostedChoice).plan
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	netReq := sandbox.NetRequest{Egress: hostedHostEgress(vocab.Tier(plan.Tier)), ProxyPort: d.r.proxyPort}
	netReq.HostSocketDir = filepath.Join(os.TempDir(), "observer-sbx-"+created.Run.ID)
	host, err := sandbox.RelayHostArgv(d.r.observerBin, netReq, nil, sandbox.RelayRequest{RunID: created.Run.ID, HostObserverDir: d.r.observerDir})
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	planPath, err := writeHostedPlan(d.r.observerDir, plan)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	d.r.unattached.Delete(created.Run.ID)
	wrap := []string{d.r.observerBin, hostedHostVerb, "--plan", planPath, "--"}
	wrap = append(wrap, host...)
	return termsvc.AttachResult{WrapArgv: append(wrap, hostedInnerMarker)}, nil
}

// hostedHostEgress is the tier the HOME side builds for a hosted run: the
// relay always, the model proxy forward unless the tier is none. The box's
// own egress is the vendor's (block-all or allow-all); Observer's gateway is
// never used for a hosted box.
func hostedHostEgress(t vocab.Tier) sandbox.Egress {
	if t == vocab.TierNone {
		return sandbox.Egress(vocab.TierNone)
	}
	return sandbox.Egress(vocab.TierProxyOnly)
}

// Resize is owned by the PTY: the host helper passes the terminal's size
// to the vendor (E2B's Update) or to the guest helper's control stream.
func (d *hostedDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: d.vendor.ID + ": the host helper passes the terminal's size to the box"}, nil
}

// Signal is owned by the PTY.
func (d *hostedDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: d.vendor.ID + ": the host helper forwards what the terminal sends"}, nil
}

// Copy is not offered: the workspace was uploaded and changes come back
// through the staged-diff step.
func (d *hostedDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: d.vendor.ID + ": no copy; the box's changes come back as a staged diff"}, nil
}

// Checkpoint: Observer never snapshots a hosted box; the transcript pull on
// the checkpoint timer is the host helper's.
func (d *hostedDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: d.vendor.ID + ": Observer never snapshots or pauses a hosted box; transcripts are pulled on the checkpoint timer"}, nil
}

// Stop is owned by the PTY: closing the terminal hangs up the helper, which
// pulls, deletes and confirms.
func (d *hostedDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: d.vendor.ID + ": closing the terminal pulls the transcripts and deletes the box"}, nil
}

// Destroy releases a run that never started (no box was created: Attach
// makes none).
func (d *hostedDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	hostedChoices.Delete(run.ID)
	_ = os.Remove(hostedPlanPath(d.r.observerDir, run.ID))
	return d.r.destroyBwrap(run)
}

// hostedPlanPath is a run's plan file.
func hostedPlanPath(observerDir, runID string) string {
	return filepath.Join(hostedStateDir(observerDir), "plans", runID+".json")
}

// writeHostedPlan writes a run's plan file (0600).
func writeHostedPlan(observerDir string, plan hostedPlanFile) (string, error) {
	p := hostedPlanPath(observerDir, plan.RunID)
	if err := hostedWriteOwned(p, plan); err != nil {
		return "", fmt.Errorf("terminal_sandbox: write the hosted plan: %w", err)
	}
	return p, nil
}

// readHostedPlan reads a plan file (owner-only, capped) and removes it.
func readHostedPlan(p string) (hostedPlanFile, error) {
	b, err := hostedReadOwned(p)
	_ = os.Remove(p) //nolint:gosec // G703: the plan file path the launch wrote under the state dir
	if err != nil {
		return hostedPlanFile{}, err
	}
	var plan hostedPlanFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil {
		return hostedPlanFile{}, fmt.Errorf("hosted plan: %w", err)
	}
	if plan.Version != hostedPlanVersion {
		return hostedPlanFile{}, fmt.Errorf("hosted plan: version %d, this binary reads %d (restart the daemon after an upgrade)", plan.Version, hostedPlanVersion)
	}
	if _, ok := sandboxremote.VendorFor(plan.Provider); !ok || !path.IsAbs(plan.Root) {
		return hostedPlanFile{}, errors.New("hosted plan: bad provider or root")
	}
	return plan, nil
}

// hostedBoxMinutes caps a planned box timeout at the shortest plan cap the
// vendor documents (S13: Vercel Hobby 45 minutes, E2B Hobby 60). The
// account's plan is never read from the vendor, so a create never asks for
// more than the smallest account may allow.
func hostedBoxMinutes(v sandboxremote.Vendor, planned int) int {
	if lc := v.MinLifetimeMinutes(); lc > 0 && planned > lc {
		return lc
	}
	return planned
}
